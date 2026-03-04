package com.sparrowwallet.drongo.nip05;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.SchnorrSignature;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.silentpayments.SilentPaymentAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.WebSocket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Resolves a NIP-05 identifier (user@domain) to a Silent Payment address.
 *
 * Resolution flow:
 * 1. HTTP GET https://domain/.well-known/nostr.json?name=user
 * 2. Extract hex pubkey from response
 * 3. Query Nostr relays for kind 0 (profile metadata) event
 * 4. Verify the event's Schnorr signature (BIP 340) against the pubkey
 * 5. Extract "sp" field from profile content
 * 6. Parse as SilentPaymentAddress
 */
public class Nip05Resolver {
    private static final Logger log = LoggerFactory.getLogger(Nip05Resolver.class);

    private static final List<String> FALLBACK_RELAYS = List.of(
            "wss://purplepag.es",
            "wss://relay.damus.io",
            "wss://nos.lol",
            "wss://relay.nostr.band"
    );

    private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration RELAY_TIMEOUT = Duration.ofSeconds(10);

    // Simple JSON extraction patterns — avoids adding a JSON library dependency to Drongo
    private static final Pattern NAMES_PATTERN = Pattern.compile("\"names\"\\s*:\\s*\\{([^}]*)\\}");
    private static final Pattern RELAYS_PATTERN = Pattern.compile("\"relays\"\\s*:\\s*\\{([^}]*)\\}");
    private static final Pattern HEX_PUBKEY_PATTERN = Pattern.compile("\"([0-9a-f]{64})\"");
    private static final Pattern RELAY_URLS_PATTERN = Pattern.compile("\"(wss?://[^\"]+)\"");
    private static final Pattern SP_FIELD_PATTERN = Pattern.compile("\"sp\"\\s*:\\s*\"(sp1[a-zA-HJ-NP-Z0-9]+)\"");

    // Patterns for extracting Nostr event fields
    private static final Pattern EVENT_PUBKEY_PATTERN = Pattern.compile("\"pubkey\"\\s*:\\s*\"([0-9a-f]{64})\"");
    private static final Pattern EVENT_ID_PATTERN = Pattern.compile("\"id\"\\s*:\\s*\"([0-9a-f]{64})\"");
    private static final Pattern EVENT_SIG_PATTERN = Pattern.compile("\"sig\"\\s*:\\s*\"([0-9a-f]{128})\"");
    private static final Pattern EVENT_KIND_PATTERN = Pattern.compile("\"kind\"\\s*:\\s*(\\d+)");
    private static final Pattern EVENT_CREATED_AT_PATTERN = Pattern.compile("\"created_at\"\\s*:\\s*(\\d+)");

    private final String hrn;
    private final String user;
    private final String domain;

    public Nip05Resolver(String hrn) {
        if(!StandardCharsets.US_ASCII.newEncoder().canEncode(hrn)) {
            throw new IllegalArgumentException("Invalid NIP-05 identifier containing non-ASCII characters: " + hrn);
        }
        this.hrn = hrn;
        String[] parts = hrn.split("@");
        if(parts.length != 2) {
            throw new IllegalArgumentException("Invalid NIP-05 identifier: " + hrn);
        }
        this.user = parts[0];
        this.domain = parts[1];
    }

    /**
     * Resolves the NIP-05 identifier to a Silent Payment address.
     *
     * @return the resolved payment, or empty if no SP address found
     * @throws Nip05Exception if resolution fails due to network or parsing errors
     */
    public Optional<Nip05Payment> resolve() throws Nip05Exception {
        log.info("Resolving NIP-05 identifier: " + hrn);

        // Step 1: Fetch nostr.json
        String nostrJsonUrl = "https://" + domain + "/.well-known/nostr.json?name=" + user;
        String nostrJsonResponse;
        try {
            nostrJsonResponse = httpGet(nostrJsonUrl);
        } catch(Exception e) {
            log.debug("Failed to fetch nostr.json from " + domain + ": " + e.getMessage());
            return Optional.empty();
        }

        // Step 2: Extract pubkey
        String pubkey = extractPubkey(nostrJsonResponse, user);
        if(pubkey == null) {
            log.debug("No pubkey found for " + user + " at " + domain);
            return Optional.empty();
        }
        log.info("Resolved " + hrn + " to Nostr pubkey");

        // Step 3: Get relay hints (or use fallbacks)
        List<String> relays = extractRelays(nostrJsonResponse, pubkey);
        if(relays.isEmpty()) {
            relays = FALLBACK_RELAYS;
        } else {
            // Append fallback relays in case the hinted ones are down
            List<String> combined = new ArrayList<>(relays);
            for(String fallback : FALLBACK_RELAYS) {
                if(!combined.contains(fallback)) {
                    combined.add(fallback);
                }
            }
            relays = combined;
        }

        // Step 4: Query relays for kind 0 event (returns raw event JSON)
        String rawEvent = queryRelaysForProfile(pubkey, relays);
        if(rawEvent == null) {
            log.info("No kind 0 event found on any relay for " + hrn);
            return Optional.empty();
        }

        // Step 5: Verify the event signature
        if(!verifyEventSignature(rawEvent, pubkey)) {
            log.warn("Event signature verification FAILED for " + hrn + " — possible relay tampering");
            throw new Nip05Exception("Nostr event signature verification failed for " + hrn + ". The event may have been tampered with.");
        }
        log.info("Event signature verified for " + hrn);

        // Step 6: Extract content from verified event
        String profileJson = extractEventContent(rawEvent);
        if(profileJson == null) {
            return Optional.empty();
        }

        // Step 7: Extract SP address from profile
        String spAddress = extractSpAddress(profileJson);
        if(spAddress == null) {
            log.info("No 'sp' field found in Nostr profile for " + hrn);
            return Optional.empty();
        }
        log.info("Found Silent Payment address for " + hrn);

        // Step 8: Parse SP address
        try {
            SilentPaymentAddress silentPaymentAddress = SilentPaymentAddress.from(spAddress);
            Nip05Payment payment = new Nip05Payment(hrn, silentPaymentAddress, pubkey, true);
            Nip05PaymentCache.putNip05Payment(hrn, payment);
            return Optional.of(payment);
        } catch(Exception e) {
            throw new Nip05Exception("Invalid Silent Payment address in profile for " + hrn + ": " + e.getMessage(), e);
        }
    }

    /**
     * Verify the Schnorr signature on a Nostr event.
     *
     * Nostr events are signed per NIP-01:
     * 1. Serialize: [0, pubkey, created_at, kind, tags, content]
     * 2. SHA-256 hash the serialized JSON → event ID
     * 3. Verify that event.id matches the computed hash
     * 4. Verify that event.sig is a valid BIP-340 Schnorr signature of the event ID using the pubkey
     *
     * @param rawEvent the raw event JSON object (the third element of the EVENT message)
     * @param expectedPubkey the hex pubkey we expect the event to be signed by
     * @return true if the signature is valid, false otherwise
     */
    boolean verifyEventSignature(String rawEvent, String expectedPubkey) {
        try {
            // Extract event fields
            String eventPubkey = extractField(rawEvent, EVENT_PUBKEY_PATTERN);
            String eventId = extractField(rawEvent, EVENT_ID_PATTERN);
            String eventSig = extractField(rawEvent, EVENT_SIG_PATTERN);
            String eventKind = extractField(rawEvent, EVENT_KIND_PATTERN);
            String eventCreatedAt = extractField(rawEvent, EVENT_CREATED_AT_PATTERN);

            if(eventPubkey == null || eventId == null || eventSig == null || eventKind == null || eventCreatedAt == null) {
                return false;
            }

            // Verify the pubkey matches what we expect from NIP-05
            if(!eventPubkey.equals(expectedPubkey)) {
                log.warn("Event pubkey does not match expected NIP-05 pubkey");
                return false;
            }

            // Extract tags and content as raw JSON strings for serialization
            String tagsJson = extractTagsJson(rawEvent);
            String contentJsonRaw = extractContentJsonRaw(rawEvent);

            if(tagsJson == null || contentJsonRaw == null) {
                return false;
            }

            // Normalize the content JSON: decode unicode escapes and re-encode canonically.
            // Relays may re-encode characters like > as unicode escapes, which changes the hash.
            // NIP-01 requires the canonical serialization to match what was originally signed.
            String contentJson = normalizeJsonString(contentJsonRaw);

            // Also normalize tags — relay may re-encode unicode in tag values
            String normalizedTagsJson = normalizeJsonArray(tagsJson);

            // Serialize per NIP-01: [0,"<pubkey>",<created_at>,<kind>,<tags>,<content>]
            String serialized = "[0,\"" + eventPubkey + "\"," + eventCreatedAt + "," + eventKind + "," + normalizedTagsJson + "," + contentJson + "]";

            // Compute SHA-256 of the serialized event
            byte[] hash = Sha256Hash.hash(serialized.getBytes(StandardCharsets.UTF_8));
            String computedId = Utils.bytesToHex(hash);

            // Verify the event ID matches the computed hash
            if(!computedId.equals(eventId)) {
                log.warn("Computed event ID does not match claimed ID — possible tampering");
                return false;
            }

            // Verify the Schnorr signature
            byte[] sigBytes = Utils.hexToBytes(eventSig);
            byte[] pubkeyBytes = Utils.hexToBytes(eventPubkey);
            SchnorrSignature signature = SchnorrSignature.decode(sigBytes);

            return signature.verify(hash, pubkeyBytes);
        } catch(Exception e) {
            log.warn("Event signature verification error: " + e.getMessage());
            return false;
        }
    }

    /**
     * Normalize a JSON string value by decoding all unicode escapes and re-encoding canonically.
     * Input must be a quoted JSON string (e.g., "hello world" with escapes).
     * Output is the canonical JSON encoding where only required characters are escaped.
     *
     * This is necessary because relays may re-encode characters (e.g., > as unicode escapes),
     * but the event ID was computed using the canonical form from the signing client.
     */
    String normalizeJsonString(String quotedJsonString) {
        if(quotedJsonString == null || quotedJsonString.length() < 2) {
            return quotedJsonString;
        }

        // Strip the outer quotes
        String inner = quotedJsonString.substring(1, quotedJsonString.length() - 1);

        // Decode all escape sequences to get the actual string value
        StringBuilder decoded = new StringBuilder();
        boolean escaped = false;
        for(int i = 0; i < inner.length(); i++) {
            char c = inner.charAt(i);
            if(escaped) {
                switch(c) {
                    case '"': decoded.append('"'); break;
                    case '\\': decoded.append('\\'); break;
                    case '/': decoded.append('/'); break;
                    case 'n': decoded.append('\n'); break;
                    case 'r': decoded.append('\r'); break;
                    case 't': decoded.append('\t'); break;
                    case 'b': decoded.append('\b'); break;
                    case 'f': decoded.append('\f'); break;
                    case 'u':
                        if(i + 4 < inner.length()) {
                            String hex = inner.substring(i + 1, i + 5);
                            try {
                                int codePoint = Integer.parseInt(hex, 16);
                                // Handle surrogate pairs for characters above U+FFFF
                                if(Character.isHighSurrogate((char)codePoint) && i + 10 < inner.length()
                                        && inner.charAt(i + 5) == '\\' && inner.charAt(i + 6) == 'u') {
                                    String lowHex = inner.substring(i + 7, i + 11);
                                    int lowSurrogate = Integer.parseInt(lowHex, 16);
                                    decoded.append(Character.toChars(Character.toCodePoint((char)codePoint, (char)lowSurrogate)));
                                    i += 10;
                                } else {
                                    decoded.append((char)codePoint);
                                    i += 4;
                                }
                            } catch(NumberFormatException e) {
                                decoded.append('u');
                            }
                        }
                        break;
                    default: decoded.append(c); break;
                }
                escaped = false;
            } else if(c == '\\') {
                escaped = true;
            } else {
                decoded.append(c);
            }
        }

        // Re-encode as canonical JSON string (minimal escaping)
        StringBuilder encoded = new StringBuilder("\"");
        for(int i = 0; i < decoded.length(); i++) {
            char c = decoded.charAt(i);
            switch(c) {
                case '"': encoded.append("\\\""); break;
                case '\\': encoded.append("\\\\"); break;
                case '\n': encoded.append("\\n"); break;
                case '\r': encoded.append("\\r"); break;
                case '\t': encoded.append("\\t"); break;
                case '\b': encoded.append("\\b"); break;
                case '\f': encoded.append("\\f"); break;
                default:
                    if(c < 0x20) {
                        encoded.append("\\");
                        encoded.append(String.format("u%04x", (int)c));
                    } else {
                        encoded.append(c);
                    }
                    break;
            }
        }
        encoded.append("\"");

        return encoded.toString();
    }

    /**
     * Normalize a JSON array by decoding and re-encoding all string values within it.
     * This handles the case where relay may re-encode unicode in tag values.
     */
    String normalizeJsonArray(String jsonArray) {
        if(jsonArray == null) {
            return null;
        }

        StringBuilder result = new StringBuilder();
        boolean inString = false;
        boolean escaped = false;
        int stringStart = -1;

        for(int i = 0; i < jsonArray.length(); i++) {
            char c = jsonArray.charAt(i);
            if(escaped) {
                escaped = false;
                continue;
            }
            if(c == '\\' && inString) {
                escaped = true;
                continue;
            }
            if(c == '"') {
                if(!inString) {
                    inString = true;
                    stringStart = i;
                } else {
                    inString = false;
                    // Extract the quoted string and normalize it
                    String quotedStr = jsonArray.substring(stringStart, i + 1);
                    String normalized = normalizeJsonString(quotedStr);
                    result.append(normalized);
                    stringStart = -1;
                    continue;
                }
                continue;
            }
            if(!inString) {
                result.append(c);
            }
        }

        return result.toString();
    }

    /**
     * Extract the "tags" field as raw JSON from the event.
     * Tags is a JSON array of arrays, e.g. [["p","abc"],["e","def"]]
     */
    String extractTagsJson(String eventJson) {
        int tagsIdx = eventJson.indexOf("\"tags\"");
        if(tagsIdx < 0) {
            return null;
        }

        int colonIdx = eventJson.indexOf(':', tagsIdx + 5);
        if(colonIdx < 0) {
            return null;
        }

        // Skip whitespace to find the opening bracket
        int start = colonIdx + 1;
        while(start < eventJson.length() && Character.isWhitespace(eventJson.charAt(start))) {
            start++;
        }

        if(start >= eventJson.length() || eventJson.charAt(start) != '[') {
            return null;
        }

        // Find the matching closing bracket, accounting for nested arrays
        int depth = 0;
        boolean inString = false;
        boolean escaped = false;
        for(int i = start; i < eventJson.length(); i++) {
            char c = eventJson.charAt(i);
            if(escaped) {
                escaped = false;
                continue;
            }
            if(c == '\\' && inString) {
                escaped = true;
                continue;
            }
            if(c == '"') {
                inString = !inString;
                continue;
            }
            if(!inString) {
                if(c == '[') depth++;
                else if(c == ']') {
                    depth--;
                    if(depth == 0) {
                        return eventJson.substring(start, i + 1);
                    }
                }
            }
        }

        return null;
    }

    /**
     * Extract the "content" field as a raw JSON string (including quotes) from the event.
     * This preserves the exact JSON encoding needed for serialization/hashing.
     */
    String extractContentJsonRaw(String eventJson) {
        int contentIdx = eventJson.indexOf("\"content\"");
        if(contentIdx < 0) {
            return null;
        }

        int colonIdx = eventJson.indexOf(':', contentIdx + 9);
        if(colonIdx < 0) {
            return null;
        }

        // Skip whitespace to find the opening quote
        int start = colonIdx + 1;
        while(start < eventJson.length() && Character.isWhitespace(eventJson.charAt(start))) {
            start++;
        }

        if(start >= eventJson.length() || eventJson.charAt(start) != '"') {
            return null;
        }

        // Find the closing quote, handling escapes
        boolean escaped = false;
        for(int i = start + 1; i < eventJson.length(); i++) {
            char c = eventJson.charAt(i);
            if(escaped) {
                escaped = false;
                continue;
            }
            if(c == '\\') {
                escaped = true;
                continue;
            }
            if(c == '"') {
                return eventJson.substring(start, i + 1);
            }
        }

        return null;
    }

    private String extractField(String json, Pattern pattern) {
        Matcher matcher = pattern.matcher(json);
        if(matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    private String httpGet(String url) throws Exception {
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(HTTP_TIMEOUT)
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(HTTP_TIMEOUT)
                .header("Accept", "application/json")
                .GET()
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if(response.statusCode() != 200) {
            throw new Nip05Exception("HTTP " + response.statusCode() + " from " + url);
        }

        return response.body();
    }

    /**
     * Extract the hex pubkey for the given user from the nostr.json response.
     * Handles the JSON format: {"names": {"user": "hex_pubkey"}}
     */
    String extractPubkey(String json, String username) {
        Matcher namesMatcher = NAMES_PATTERN.matcher(json);
        if(!namesMatcher.find()) {
            return null;
        }

        String namesBlock = namesMatcher.group(1);
        // Look for "username": "hex_pubkey"
        Pattern userPattern = Pattern.compile("\"" + Pattern.quote(username) + "\"\\s*:\\s*\"([0-9a-f]{64})\"");
        Matcher userMatcher = userPattern.matcher(namesBlock);
        if(userMatcher.find()) {
            return userMatcher.group(1);
        }

        return null;
    }

    /**
     * Extract relay hints for the given pubkey from the nostr.json response.
     * Handles the JSON format: {"relays": {"hex_pubkey": ["wss://relay1", ...]}}
     */
    List<String> extractRelays(String json, String pubkey) {
        // The relays block can be complex — look for the pubkey within the relays section
        // Format: "relays": { "pubkey": ["wss://...", ...] }
        Pattern relayForPubkey = Pattern.compile(
                "\"relays\"\\s*:\\s*\\{[^}]*\"" + Pattern.quote(pubkey) + "\"\\s*:\\s*\\[([^\\]]*)\\]",
                Pattern.DOTALL
        );
        Matcher matcher = relayForPubkey.matcher(json);
        if(!matcher.find()) {
            return Collections.emptyList();
        }

        String relayArray = matcher.group(1);
        List<String> relays = new ArrayList<>();
        Matcher urlMatcher = RELAY_URLS_PATTERN.matcher(relayArray);
        while(urlMatcher.find()) {
            relays.add(urlMatcher.group(1));
        }

        return relays;
    }

    /**
     * Query Nostr relays for the kind 0 (metadata) event for the given pubkey.
     * Tries relays sequentially, returns the first successful raw event JSON.
     */
    String queryRelaysForProfile(String pubkey, List<String> relays) {
        // Nostr subscription request: REQ with filter for kind 0
        String subscriptionId = UUID.randomUUID().toString().substring(0, 8);
        String reqMessage = "[\"REQ\",\"" + subscriptionId + "\",{\"kinds\":[0],\"authors\":[\"" + pubkey + "\"],\"limit\":1}]";
        String closeMessage = "[\"CLOSE\",\"" + subscriptionId + "\"]";

        for(String relayUrl : relays) {
            try {
                String result = queryRelay(relayUrl, reqMessage, closeMessage, subscriptionId);
                if(result != null) {
                    return result;
                }
            } catch(Exception e) {
                log.debug("Failed to query relay " + relayUrl + ": " + e.getMessage());
            }
        }

        return null;
    }

    /**
     * Connect to a single relay via WebSocket, send a subscription, and read the response.
     * Returns the raw event JSON object (third element of the EVENT message array), or null if not found.
     */
    String queryRelay(String relayUrl, String reqMessage, String closeMessage, String subscriptionId) throws Exception {
        CompletableFuture<String> resultFuture = new CompletableFuture<>();

        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(RELAY_TIMEOUT)
                .build();

        StringBuilder messageBuffer = new StringBuilder();

        WebSocket webSocket = client.newWebSocketBuilder()
                .connectTimeout(RELAY_TIMEOUT)
                .buildAsync(URI.create(relayUrl), new WebSocket.Listener() {
                    @Override
                    public void onOpen(WebSocket webSocket) {
                        webSocket.sendText(reqMessage, true);
                        webSocket.request(1);
                    }

                    @Override
                    public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
                        messageBuffer.append(data);
                        if(last) {
                            String message = messageBuffer.toString();
                            messageBuffer.setLength(0);
                            handleRelayMessage(message, subscriptionId, resultFuture);
                        }
                        webSocket.request(1);
                        return null;
                    }

                    @Override
                    public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
                        if(!resultFuture.isDone()) {
                            resultFuture.complete(null);
                        }
                        return null;
                    }

                    @Override
                    public void onError(WebSocket webSocket, Throwable error) {
                        if(!resultFuture.isDone()) {
                            resultFuture.completeExceptionally(error);
                        }
                    }
                }).join();

        try {
            String result = resultFuture.get(RELAY_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
            webSocket.sendText(closeMessage, true);
            webSocket.sendClose(WebSocket.NORMAL_CLOSURE, "done");
            return result;
        } catch(Exception e) {
            try {
                webSocket.sendClose(WebSocket.NORMAL_CLOSURE, "timeout");
            } catch(Exception ignored) {}
            throw e;
        }
    }

    /**
     * Handle a message from a Nostr relay. Messages are JSON arrays:
     * - ["EVENT", subscription_id, event_object] — an event matching our subscription
     * - ["EOSE", subscription_id] — end of stored events
     * - ["NOTICE", message] — relay notice
     *
     * Now returns the raw event JSON object (not just the content) for signature verification.
     */
    void handleRelayMessage(String message, String subscriptionId, CompletableFuture<String> resultFuture) {
        if(resultFuture.isDone()) {
            return;
        }

        // Check for EVENT message
        if(message.startsWith("[\"EVENT\"")) {
            // Extract the raw event object (third element of the array)
            String rawEvent = extractRawEventObject(message);
            if(rawEvent != null) {
                resultFuture.complete(rawEvent);
                return;
            }
        }

        // Check for EOSE (end of stored events) — no more events coming
        if(message.startsWith("[\"EOSE\"")) {
            if(!resultFuture.isDone()) {
                resultFuture.complete(null);
            }
        }
    }

    /**
     * Extract the raw event JSON object from an EVENT message.
     * EVENT messages are: ["EVENT", "subscription_id", {event_object}]
     * We need the {event_object} part as-is for signature verification.
     */
    String extractRawEventObject(String eventMessage) {
        // Find the opening brace of the event object
        int braceStart = eventMessage.indexOf('{');
        if(braceStart < 0) {
            return null;
        }

        // Find the matching closing brace
        int depth = 0;
        boolean inString = false;
        boolean escaped = false;
        for(int i = braceStart; i < eventMessage.length(); i++) {
            char c = eventMessage.charAt(i);
            if(escaped) {
                escaped = false;
                continue;
            }
            if(c == '\\' && inString) {
                escaped = true;
                continue;
            }
            if(c == '"') {
                inString = !inString;
                continue;
            }
            if(!inString) {
                if(c == '{') depth++;
                else if(c == '}') {
                    depth--;
                    if(depth == 0) {
                        return eventMessage.substring(braceStart, i + 1);
                    }
                }
            }
        }

        return null;
    }

    /**
     * Extract the "content" field value from a Nostr event object.
     * The content of a kind 0 event is a JSON string containing the profile metadata.
     * It is itself JSON-encoded (escaped) within the event object.
     */
    String extractEventContent(String eventMessage) {
        // Find "content":"..." in the event object
        // The content value is a JSON-escaped string containing the profile JSON
        int contentIdx = eventMessage.indexOf("\"content\"");
        if(contentIdx < 0) {
            return null;
        }

        // Find the opening quote of the value
        int colonIdx = eventMessage.indexOf(':', contentIdx + 9);
        if(colonIdx < 0) {
            return null;
        }

        // Skip whitespace to find the opening quote
        int valueStart = colonIdx + 1;
        while(valueStart < eventMessage.length() && eventMessage.charAt(valueStart) == ' ') {
            valueStart++;
        }

        if(valueStart >= eventMessage.length() || eventMessage.charAt(valueStart) != '"') {
            return null;
        }

        // Parse the JSON string value, handling escaped characters
        StringBuilder content = new StringBuilder();
        boolean escaped = false;
        for(int i = valueStart + 1; i < eventMessage.length(); i++) {
            char c = eventMessage.charAt(i);
            if(escaped) {
                switch(c) {
                    case '"': content.append('"'); break;
                    case '\\': content.append('\\'); break;
                    case '/': content.append('/'); break;
                    case 'n': content.append('\n'); break;
                    case 'r': content.append('\r'); break;
                    case 't': content.append('\t'); break;
                    case 'u':
                        if(i + 4 < eventMessage.length()) {
                            String hex = eventMessage.substring(i + 1, i + 5);
                            content.append((char)Integer.parseInt(hex, 16));
                            i += 4;
                        }
                        break;
                    default: content.append(c); break;
                }
                escaped = false;
            } else if(c == '\\') {
                escaped = true;
            } else if(c == '"') {
                break; // End of string
            } else {
                content.append(c);
            }
        }

        return content.toString();
    }

    /**
     * Extract the Silent Payment address from a kind 0 profile content JSON.
     * Looks for "sp": "sp1..." in the profile metadata.
     */
    String extractSpAddress(String profileJson) {
        Matcher matcher = SP_FIELD_PATTERN.matcher(profileJson);
        if(matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    public String getHrn() {
        return hrn;
    }
}
