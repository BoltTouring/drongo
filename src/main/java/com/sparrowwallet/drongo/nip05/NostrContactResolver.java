package com.sparrowwallet.drongo.nip05;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.SchnorrSignature;
import com.sparrowwallet.drongo.protocol.Bech32;
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
import java.util.concurrent.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Resolves a Nostr user's follow list (kind 3) and batch-resolves their contacts'
 * kind 0 profiles to find Silent Payment addresses.
 *
 * Resolution flow:
 * 1. Decode npub (bech32) or resolve NIP-05 identifier to hex pubkey
 * 2. Query relays for kind 3 (contacts) event
 * 3. Verify kind 3 event signature
 * 4. Extract contact pubkeys from "p" tags
 * 5. Batch-query relays for kind 0 (profile) events for all contacts
 * 6. Extract name, sp, nip05, picture from each profile
 * 7. Return sorted list of NostrContact objects
 */
public class NostrContactResolver {
    private static final Logger log = LoggerFactory.getLogger(NostrContactResolver.class);

    private static final List<String> FALLBACK_RELAYS = List.of(
            "wss://purplepag.es",
            "wss://relay.damus.io",
            "wss://nos.lol",
            "wss://relay.nostr.band"
    );

    private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration RELAY_TIMEOUT = Duration.ofSeconds(15);

    // Nostr event field patterns (same as Nip05Resolver)
    private static final Pattern EVENT_PUBKEY_PATTERN = Pattern.compile("\"pubkey\"\\s*:\\s*\"([0-9a-f]{64})\"");
    private static final Pattern EVENT_ID_PATTERN = Pattern.compile("\"id\"\\s*:\\s*\"([0-9a-f]{64})\"");
    private static final Pattern EVENT_SIG_PATTERN = Pattern.compile("\"sig\"\\s*:\\s*\"([0-9a-f]{128})\"");
    private static final Pattern EVENT_KIND_PATTERN = Pattern.compile("\"kind\"\\s*:\\s*(\\d+)");
    private static final Pattern EVENT_CREATED_AT_PATTERN = Pattern.compile("\"created_at\"\\s*:\\s*(\\d+)");

    // Profile field patterns
    private static final Pattern SP_FIELD_PATTERN = Pattern.compile("\"sp\"\\s*:\\s*\"(sp1[a-zA-HJ-NP-Z0-9]+)\"");
    private static final Pattern NAME_FIELD_PATTERN = Pattern.compile("\"name\"\\s*:\\s*\"([^\"]{0,100})\"");
    private static final Pattern NIP05_FIELD_PATTERN = Pattern.compile("\"nip05\"\\s*:\\s*\"([^\"]{0,200})\"");
    private static final Pattern PICTURE_FIELD_PATTERN = Pattern.compile("\"picture\"\\s*:\\s*\"([^\"]{0,500})\"");

    // Contact tag pattern: ["p","<hex64>",...]
    private static final Pattern CONTACT_TAG_PATTERN = Pattern.compile("\"p\"\\s*,\\s*\"([0-9a-f]{64})\"");

    // NIP-05 nostr.json patterns (reused from Nip05Resolver)
    private static final Pattern NAMES_PATTERN = Pattern.compile("\"names\"\\s*:\\s*\\{([^}]*)\\}");

    private final String input;

    /**
     * Create a resolver for the given npub or NIP-05 identifier.
     *
     * @param npubOrNip05 either "npub1..." bech32 key or "user@domain" NIP-05 identifier
     */
    public NostrContactResolver(String npubOrNip05) {
        this.input = npubOrNip05.trim();
    }

    /**
     * Resolve the user's Nostr contacts and their Silent Payment addresses.
     *
     * @return list of contacts, sorted with SP-enabled contacts first
     * @throws Nip05Exception on resolution failures
     */
    public List<NostrContact> resolveContacts() throws Nip05Exception {
        log.info("Resolving Nostr contacts for: " + input);

        // Step 1: Get hex pubkey
        String hexPubkey = resolveToHexPubkey(input);
        log.info("Resolved to pubkey: " + hexPubkey.substring(0, 8) + "...");

        // Step 2: Query relays for kind 3 (contacts) event
        String kind3Event = queryRelaysForEvent(hexPubkey, 3, FALLBACK_RELAYS);
        if(kind3Event == null) {
            throw new Nip05Exception("No contact list found on any relay for " + input);
        }

        // Step 3: Verify kind 3 signature
        if(!verifyEventSignature(kind3Event, hexPubkey)) {
            throw new Nip05Exception("Contact list signature verification failed for " + input);
        }
        log.info("Contact list signature verified");

        // Step 4: Extract contact pubkeys from tags
        List<String> contactPubkeys = extractContactPubkeys(kind3Event);
        if(contactPubkeys.isEmpty()) {
            log.info("No contacts found in follow list for " + input);
            return Collections.emptyList();
        }
        log.info("Found " + contactPubkeys.size() + " contacts in follow list");

        // Step 5: Batch-query kind 0 profiles
        Map<String, String> profiles = batchQueryProfiles(contactPubkeys, FALLBACK_RELAYS);
        log.info("Resolved " + profiles.size() + " profiles from relays");

        // Step 6: Build NostrContact list from profiles
        List<NostrContact> contacts = new ArrayList<>();
        for(String pubkey : contactPubkeys) {
            String rawEvent = profiles.get(pubkey);
            if(rawEvent != null) {
                boolean sigVerified = verifyEventSignature(rawEvent, pubkey);
                String profileJson = extractEventContent(rawEvent);
                if(profileJson != null) {
                    contacts.add(buildContact(pubkey, profileJson, sigVerified));
                    continue;
                }
            }
            // No profile found — create placeholder
            contacts.add(new NostrContact(pubkey, abbreviatePubkey(pubkey), null, null, null, false));
        }

        // Sort: SP contacts first, then alphabetical by display name
        contacts.sort((a, b) -> {
            if(a.hasSilentPaymentAddress() != b.hasSilentPaymentAddress()) {
                return a.hasSilentPaymentAddress() ? -1 : 1;
            }
            return a.displayName().compareToIgnoreCase(b.displayName());
        });

        int spCount = (int) contacts.stream().filter(NostrContact::hasSilentPaymentAddress).count();
        log.info("Resolved " + contacts.size() + " contacts (" + spCount + " with Silent Payment address)");

        return contacts;
    }

    /**
     * Convert npub or NIP-05 input to hex pubkey.
     */
    String resolveToHexPubkey(String input) throws Nip05Exception {
        if(input.startsWith("npub1")) {
            return npubToHex(input);
        } else if(input.contains("@")) {
            return nip05ToHex(input);
        } else if(input.matches("[0-9a-f]{64}")) {
            return input;
        } else {
            throw new Nip05Exception("Invalid input: expected npub, NIP-05 identifier, or hex pubkey");
        }
    }

    /**
     * Decode an npub bech32 string to a hex pubkey.
     */
    String npubToHex(String npub) throws Nip05Exception {
        try {
            Bech32.Bech32Data decoded = Bech32.decode(npub, 90);
            if(!decoded.hrp.equals("npub")) {
                throw new Nip05Exception("Invalid npub prefix: " + decoded.hrp);
            }
            // Convert from 5-bit groups to 8-bit bytes
            byte[] pubkeyBytes = Bech32.convertBits(decoded.data, 0, decoded.data.length, 5, 8, false);
            if(pubkeyBytes.length != 32) {
                throw new Nip05Exception("Invalid npub: decoded to " + pubkeyBytes.length + " bytes, expected 32");
            }
            return Utils.bytesToHex(pubkeyBytes);
        } catch(Nip05Exception e) {
            throw e;
        } catch(Exception e) {
            throw new Nip05Exception("Failed to decode npub: " + e.getMessage(), e);
        }
    }

    /**
     * Resolve a NIP-05 identifier to a hex pubkey via HTTP lookup.
     */
    private String nip05ToHex(String nip05) throws Nip05Exception {
        String[] parts = nip05.split("@");
        if(parts.length != 2) {
            throw new Nip05Exception("Invalid NIP-05 identifier: " + nip05);
        }
        String user = parts[0];
        String domain = parts[1];

        String url = "https://" + domain + "/.well-known/nostr.json?name=" + user;
        try {
            String response = httpGet(url);
            Matcher namesMatcher = NAMES_PATTERN.matcher(response);
            if(!namesMatcher.find()) {
                throw new Nip05Exception("No 'names' field in nostr.json from " + domain);
            }
            String namesBlock = namesMatcher.group(1);
            Pattern userPattern = Pattern.compile("\"" + Pattern.quote(user) + "\"\\s*:\\s*\"([0-9a-f]{64})\"");
            Matcher userMatcher = userPattern.matcher(namesBlock);
            if(!userMatcher.find()) {
                throw new Nip05Exception("No pubkey found for " + user + " at " + domain);
            }
            return userMatcher.group(1);
        } catch(Nip05Exception e) {
            throw e;
        } catch(Exception e) {
            throw new Nip05Exception("Failed to resolve NIP-05 " + nip05 + ": " + e.getMessage(), e);
        }
    }

    /**
     * Query relays for a single event of the given kind for the given pubkey.
     * Tries relays sequentially, returns the first successful raw event JSON.
     */
    String queryRelaysForEvent(String pubkey, int kind, List<String> relays) {
        String subscriptionId = UUID.randomUUID().toString().substring(0, 8);
        String reqMessage = "[\"REQ\",\"" + subscriptionId + "\",{\"kinds\":[" + kind + "],\"authors\":[\"" + pubkey + "\"],\"limit\":1}]";
        String closeMessage = "[\"CLOSE\",\"" + subscriptionId + "\"]";

        for(String relayUrl : relays) {
            try {
                String result = queryRelaySingle(relayUrl, reqMessage, closeMessage);
                if(result != null) {
                    return result;
                }
            } catch(Exception e) {
                log.debug("Failed to query relay " + relayUrl + " for kind " + kind + ": " + e.getMessage());
            }
        }
        return null;
    }

    /**
     * Extract contact pubkeys from a kind 3 event's tags.
     * Kind 3 events have tags like: [["p","hex_pubkey","relay_hint"], ...]
     */
    List<String> extractContactPubkeys(String kind3Event) {
        String tagsJson = extractTagsJson(kind3Event);
        if(tagsJson == null) {
            return Collections.emptyList();
        }

        List<String> pubkeys = new ArrayList<>();
        Matcher matcher = CONTACT_TAG_PATTERN.matcher(tagsJson);
        while(matcher.find()) {
            String pubkey = matcher.group(1);
            if(!pubkeys.contains(pubkey)) {
                pubkeys.add(pubkey);
            }
        }
        return pubkeys;
    }

    /**
     * Batch-query multiple relays for kind 0 profiles of the given pubkeys.
     * Queries relays in parallel and merges results.
     *
     * @return map of pubkey → raw event JSON for each resolved profile
     */
    Map<String, String> batchQueryProfiles(List<String> pubkeys, List<String> relays) {
        if(pubkeys.isEmpty()) {
            return Collections.emptyMap();
        }

        // Build the authors array for the REQ filter
        StringBuilder authorsArray = new StringBuilder();
        for(int i = 0; i < pubkeys.size(); i++) {
            if(i > 0) authorsArray.append(",");
            authorsArray.append("\"").append(pubkeys.get(i)).append("\"");
        }

        String subscriptionId = UUID.randomUUID().toString().substring(0, 8);
        String reqMessage = "[\"REQ\",\"" + subscriptionId + "\",{\"kinds\":[0],\"authors\":[" + authorsArray + "]}]";
        String closeMessage = "[\"CLOSE\",\"" + subscriptionId + "\"]";

        // Query relays in parallel
        Map<String, String> mergedResults = new ConcurrentHashMap<>();
        List<CompletableFuture<Map<String, String>>> futures = new ArrayList<>();

        for(String relayUrl : relays) {
            futures.add(CompletableFuture.supplyAsync(() -> {
                try {
                    return queryRelayBatch(relayUrl, reqMessage, closeMessage);
                } catch(Exception e) {
                    log.debug("Batch query failed for relay " + relayUrl + ": " + e.getMessage());
                    return Collections.<String, String>emptyMap();
                }
            }));
        }

        try {
            // Wait for all relays with a global timeout
            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                    .get(RELAY_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
        } catch(TimeoutException e) {
            log.debug("Some relays timed out during batch query");
        } catch(Exception e) {
            log.debug("Error during batch query: " + e.getMessage());
        }

        // Merge results — prefer events we haven't seen yet
        for(CompletableFuture<Map<String, String>> future : futures) {
            try {
                if(future.isDone() && !future.isCompletedExceptionally()) {
                    Map<String, String> relayResults = future.get(0, TimeUnit.MILLISECONDS);
                    for(Map.Entry<String, String> entry : relayResults.entrySet()) {
                        mergedResults.putIfAbsent(entry.getKey(), entry.getValue());
                    }
                }
            } catch(Exception ignored) {}
        }

        return mergedResults;
    }

    /**
     * Query a single relay for a batch of kind 0 profiles.
     * Returns a map of pubkey → raw event JSON.
     */
    private Map<String, String> queryRelayBatch(String relayUrl, String reqMessage, String closeMessage) throws Exception {
        CompletableFuture<Map<String, String>> resultFuture = new CompletableFuture<>();
        Map<String, String> results = new ConcurrentHashMap<>();

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
                            handleBatchMessage(message, results, resultFuture);
                        }
                        webSocket.request(1);
                        return null;
                    }

                    @Override
                    public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
                        if(!resultFuture.isDone()) {
                            resultFuture.complete(results);
                        }
                        return null;
                    }

                    @Override
                    public void onError(WebSocket webSocket, Throwable error) {
                        if(!resultFuture.isDone()) {
                            resultFuture.complete(results); // Return whatever we got
                        }
                    }
                }).join();

        try {
            Map<String, String> result = resultFuture.get(RELAY_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
            webSocket.sendText(closeMessage, true);
            webSocket.sendClose(WebSocket.NORMAL_CLOSURE, "done");
            return result;
        } catch(Exception e) {
            try {
                webSocket.sendClose(WebSocket.NORMAL_CLOSURE, "timeout");
            } catch(Exception ignored) {}
            return results; // Return whatever we accumulated
        }
    }

    /**
     * Handle a relay message during batch query.
     * Accumulates EVENT messages until EOSE.
     */
    private void handleBatchMessage(String message, Map<String, String> results, CompletableFuture<Map<String, String>> resultFuture) {
        if(resultFuture.isDone()) {
            return;
        }

        if(message.startsWith("[\"EVENT\"")) {
            String rawEvent = extractRawEventObject(message);
            if(rawEvent != null) {
                // Extract the pubkey from the event to use as map key
                Matcher pubkeyMatcher = EVENT_PUBKEY_PATTERN.matcher(rawEvent);
                if(pubkeyMatcher.find()) {
                    results.put(pubkeyMatcher.group(1), rawEvent);
                }
            }
        }

        if(message.startsWith("[\"EOSE\"")) {
            resultFuture.complete(results);
        }
    }

    /**
     * Query a single relay for a single event. Returns raw event JSON or null.
     */
    private String queryRelaySingle(String relayUrl, String reqMessage, String closeMessage) throws Exception {
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
                            handleSingleMessage(message, resultFuture);
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

    private void handleSingleMessage(String message, CompletableFuture<String> resultFuture) {
        if(resultFuture.isDone()) {
            return;
        }
        if(message.startsWith("[\"EVENT\"")) {
            String rawEvent = extractRawEventObject(message);
            if(rawEvent != null) {
                resultFuture.complete(rawEvent);
                return;
            }
        }
        if(message.startsWith("[\"EOSE\"")) {
            if(!resultFuture.isDone()) {
                resultFuture.complete(null);
            }
        }
    }

    /**
     * Build a NostrContact from a profile JSON string.
     */
    private NostrContact buildContact(String pubkey, String profileJson, boolean sigVerified) {
        String name = extractField(profileJson, NAME_FIELD_PATTERN);
        String nip05 = extractField(profileJson, NIP05_FIELD_PATTERN);
        String picture = extractField(profileJson, PICTURE_FIELD_PATTERN);
        String spAddressStr = extractField(profileJson, SP_FIELD_PATTERN);

        String displayName = (name != null && !name.isEmpty()) ? name : abbreviatePubkey(pubkey);

        SilentPaymentAddress spAddress = null;
        if(spAddressStr != null) {
            try {
                spAddress = SilentPaymentAddress.from(spAddressStr);
            } catch(Exception e) {
                log.debug("Invalid SP address for " + displayName + ": " + e.getMessage());
            }
        }

        return new NostrContact(pubkey, displayName, spAddress, nip05, picture, sigVerified);
    }

    private String abbreviatePubkey(String pubkey) {
        if(pubkey == null || pubkey.length() < 12) return pubkey;
        return pubkey.substring(0, 8) + "..." + pubkey.substring(pubkey.length() - 4);
    }

    // ===== Shared event parsing methods (same logic as Nip05Resolver) =====

    boolean verifyEventSignature(String rawEvent, String expectedPubkey) {
        try {
            String eventPubkey = extractField(rawEvent, EVENT_PUBKEY_PATTERN);
            String eventId = extractField(rawEvent, EVENT_ID_PATTERN);
            String eventSig = extractField(rawEvent, EVENT_SIG_PATTERN);
            String eventKind = extractField(rawEvent, EVENT_KIND_PATTERN);
            String eventCreatedAt = extractField(rawEvent, EVENT_CREATED_AT_PATTERN);

            if(eventPubkey == null || eventId == null || eventSig == null || eventKind == null || eventCreatedAt == null) {
                return false;
            }

            if(!eventPubkey.equals(expectedPubkey)) {
                log.warn("Event pubkey does not match expected pubkey");
                return false;
            }

            String tagsJson = extractTagsJson(rawEvent);
            String contentJsonRaw = extractContentJsonRaw(rawEvent);
            if(tagsJson == null || contentJsonRaw == null) {
                return false;
            }

            String contentJson = normalizeJsonString(contentJsonRaw);
            String normalizedTagsJson = normalizeJsonArray(tagsJson);

            String serialized = "[0,\"" + eventPubkey + "\"," + eventCreatedAt + "," + eventKind + "," + normalizedTagsJson + "," + contentJson + "]";

            byte[] hash = Sha256Hash.hash(serialized.getBytes(StandardCharsets.UTF_8));
            String computedId = Utils.bytesToHex(hash);

            if(!computedId.equals(eventId)) {
                log.warn("Computed event ID does not match claimed ID");
                return false;
            }

            byte[] sigBytes = Utils.hexToBytes(eventSig);
            byte[] pubkeyBytes = Utils.hexToBytes(eventPubkey);
            SchnorrSignature signature = SchnorrSignature.decode(sigBytes);

            return signature.verify(hash, pubkeyBytes);
        } catch(Exception e) {
            log.warn("Event signature verification error: " + e.getMessage());
            return false;
        }
    }

    private String extractField(String json, Pattern pattern) {
        Matcher matcher = pattern.matcher(json);
        if(matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    String extractRawEventObject(String eventMessage) {
        int braceStart = eventMessage.indexOf('{');
        if(braceStart < 0) return null;

        int depth = 0;
        boolean inString = false;
        boolean escaped = false;
        for(int i = braceStart; i < eventMessage.length(); i++) {
            char c = eventMessage.charAt(i);
            if(escaped) { escaped = false; continue; }
            if(c == '\\' && inString) { escaped = true; continue; }
            if(c == '"') { inString = !inString; continue; }
            if(!inString) {
                if(c == '{') depth++;
                else if(c == '}') {
                    depth--;
                    if(depth == 0) return eventMessage.substring(braceStart, i + 1);
                }
            }
        }
        return null;
    }

    String extractTagsJson(String eventJson) {
        int tagsIdx = eventJson.indexOf("\"tags\"");
        if(tagsIdx < 0) return null;
        int colonIdx = eventJson.indexOf(':', tagsIdx + 5);
        if(colonIdx < 0) return null;

        int start = colonIdx + 1;
        while(start < eventJson.length() && Character.isWhitespace(eventJson.charAt(start))) start++;
        if(start >= eventJson.length() || eventJson.charAt(start) != '[') return null;

        int depth = 0;
        boolean inString = false;
        boolean escaped = false;
        for(int i = start; i < eventJson.length(); i++) {
            char c = eventJson.charAt(i);
            if(escaped) { escaped = false; continue; }
            if(c == '\\' && inString) { escaped = true; continue; }
            if(c == '"') { inString = !inString; continue; }
            if(!inString) {
                if(c == '[') depth++;
                else if(c == ']') {
                    depth--;
                    if(depth == 0) return eventJson.substring(start, i + 1);
                }
            }
        }
        return null;
    }

    String extractContentJsonRaw(String eventJson) {
        int contentIdx = eventJson.indexOf("\"content\"");
        if(contentIdx < 0) return null;
        int colonIdx = eventJson.indexOf(':', contentIdx + 9);
        if(colonIdx < 0) return null;

        int start = colonIdx + 1;
        while(start < eventJson.length() && Character.isWhitespace(eventJson.charAt(start))) start++;
        if(start >= eventJson.length() || eventJson.charAt(start) != '"') return null;

        boolean escaped = false;
        for(int i = start + 1; i < eventJson.length(); i++) {
            char c = eventJson.charAt(i);
            if(escaped) { escaped = false; continue; }
            if(c == '\\') { escaped = true; continue; }
            if(c == '"') return eventJson.substring(start, i + 1);
        }
        return null;
    }

    String extractEventContent(String eventMessage) {
        int contentIdx = eventMessage.indexOf("\"content\"");
        if(contentIdx < 0) return null;
        int colonIdx = eventMessage.indexOf(':', contentIdx + 9);
        if(colonIdx < 0) return null;

        int valueStart = colonIdx + 1;
        while(valueStart < eventMessage.length() && eventMessage.charAt(valueStart) == ' ') valueStart++;
        if(valueStart >= eventMessage.length() || eventMessage.charAt(valueStart) != '"') return null;

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
                break;
            } else {
                content.append(c);
            }
        }
        return content.toString();
    }

    // JSON normalization methods (same as Nip05Resolver)

    String normalizeJsonString(String quotedJsonString) {
        if(quotedJsonString == null || quotedJsonString.length() < 2) return quotedJsonString;

        String inner = quotedJsonString.substring(1, quotedJsonString.length() - 1);
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

    String normalizeJsonArray(String jsonArray) {
        if(jsonArray == null) return null;

        StringBuilder result = new StringBuilder();
        boolean inString = false;
        boolean escaped = false;
        int stringStart = -1;

        for(int i = 0; i < jsonArray.length(); i++) {
            char c = jsonArray.charAt(i);
            if(escaped) { escaped = false; continue; }
            if(c == '\\' && inString) { escaped = true; continue; }
            if(c == '"') {
                if(!inString) {
                    inString = true;
                    stringStart = i;
                } else {
                    inString = false;
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
}
