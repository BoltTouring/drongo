package com.sparrowwallet.drongo.nip05;

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
 * 4. Extract "sp" field from profile content
 * 5. Parse as SilentPaymentAddress
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
        log.debug("Resolving NIP-05 identifier: " + hrn);

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
        log.debug("Resolved " + hrn + " to pubkey: " + pubkey);

        // Step 3: Get relay hints (or use fallbacks)
        List<String> relays = extractRelays(nostrJsonResponse, pubkey);
        if(relays.isEmpty()) {
            log.debug("No relay hints in nostr.json, using fallback relays");
            relays = FALLBACK_RELAYS;
        } else {
            log.debug("Found relay hints: " + relays);
            // Append fallback relays in case the hinted ones are down
            List<String> combined = new ArrayList<>(relays);
            for(String fallback : FALLBACK_RELAYS) {
                if(!combined.contains(fallback)) {
                    combined.add(fallback);
                }
            }
            relays = combined;
        }

        // Step 4: Query relays for kind 0 event
        String profileJson = queryRelaysForProfile(pubkey, relays);
        if(profileJson == null) {
            log.debug("No kind 0 event found for " + pubkey + " on any relay");
            return Optional.empty();
        }

        // Step 5: Extract SP address from profile
        String spAddress = extractSpAddress(profileJson);
        if(spAddress == null) {
            log.debug("No 'sp' field found in profile for " + hrn);
            return Optional.empty();
        }
        log.debug("Found SP address for " + hrn + ": " + spAddress.substring(0, Math.min(20, spAddress.length())) + "...");

        // Step 6: Parse SP address
        try {
            SilentPaymentAddress silentPaymentAddress = SilentPaymentAddress.from(spAddress);
            Nip05Payment payment = new Nip05Payment(hrn, silentPaymentAddress, pubkey);
            Nip05PaymentCache.putNip05Payment(hrn, payment);
            return Optional.of(payment);
        } catch(Exception e) {
            throw new Nip05Exception("Invalid Silent Payment address in profile for " + hrn + ": " + e.getMessage(), e);
        }
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
     * Tries relays sequentially, returns the first successful result.
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
     * Returns the content field of the kind 0 event, or null if not found.
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
                        log.debug("Connected to relay: " + relayUrl);
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
     */
    void handleRelayMessage(String message, String subscriptionId, CompletableFuture<String> resultFuture) {
        if(resultFuture.isDone()) {
            return;
        }

        // Check for EVENT message
        if(message.startsWith("[\"EVENT\"")) {
            // Extract the content field from the kind 0 event
            // The event is the third element: ["EVENT", "sub_id", {event}]
            // The content field contains the profile JSON as a string
            String content = extractEventContent(message);
            if(content != null) {
                resultFuture.complete(content);
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
     * Extract the "content" field value from a Nostr EVENT message.
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
