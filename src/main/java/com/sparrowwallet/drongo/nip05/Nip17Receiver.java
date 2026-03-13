package com.sparrowwallet.drongo.nip05;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Receives and decrypts NIP-17 gift-wrapped DMs from Nostr relays.
 * Filters for Silent Payment notifications.
 */
public class Nip17Receiver {
    private static final Logger log = LoggerFactory.getLogger(Nip17Receiver.class);

    private static final Duration RELAY_TIMEOUT = Duration.ofSeconds(15);
    private static final int KIND_GIFT_WRAP = 1059;

    private static final Pattern PUBKEY_PATTERN = Pattern.compile("\"pubkey\"\\s*:\\s*\"([0-9a-f]{64})\"");
    private static final Pattern CONTENT_PATTERN = Pattern.compile("\"content\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
    private static final Pattern KIND_PATTERN = Pattern.compile("\"kind\"\\s*:\\s*(\\d+)");

    private static final List<String> DEFAULT_RELAYS = List.of(
            "wss://relay.damus.io",
            "wss://nos.lol",
            "wss://relay.nostr.band",
            "wss://purplepag.es"
    );

    private final String recipientPubKeyHex;
    private final DecryptFunction decryptFn;

    /**
     * Functional interface for NIP-44 decryption.
     * Takes the other party's hex pubkey and the ciphertext, returns plaintext.
     */
    @FunctionalInterface
    public interface DecryptFunction {
        String decrypt(String senderPubKeyHex, String ciphertext) throws Exception;
    }

    /**
     * Create a receiver using a local private key for decryption.
     */
    public Nip17Receiver(byte[] recipientPrivKey) {
        ECKey key = ECKey.fromPrivate(recipientPrivKey);
        this.recipientPubKeyHex = Utils.bytesToHex(key.getPubKeyXCoord());
        this.decryptFn = (senderPubKeyHex, ciphertext) -> {
            byte[] senderPubKey33 = Nip17Sender.pubKeyHexToCompressed(senderPubKeyHex);
            return Nip44.decrypt(recipientPrivKey, senderPubKey33, ciphertext);
        };
    }

    /**
     * Create a receiver using a delegate for decryption (e.g. NIP-46 bunker).
     *
     * @param recipientPubKeyHex the recipient's 64-char hex pubkey (for relay queries)
     * @param decryptFn a function that decrypts NIP-44 ciphertext given the sender's pubkey
     */
    public Nip17Receiver(String recipientPubKeyHex, DecryptFunction decryptFn) {
        this.recipientPubKeyHex = recipientPubKeyHex;
        this.decryptFn = decryptFn;
    }

    /**
     * Poll relays for SP notifications sent to this recipient.
     *
     * @param since only return events after this Unix timestamp (0 for all)
     * @param relays relay URLs to query (uses defaults if null)
     * @return list of decrypted SP notifications
     */
    public List<SilentPaymentNotification> pollNotifications(long since, List<String> relays) {
        List<String> targetRelays = relays != null ? relays : DEFAULT_RELAYS;
        Set<String> seenEvents = ConcurrentHashMap.newKeySet();
        List<SilentPaymentNotification> notifications = Collections.synchronizedList(new ArrayList<>());

        log.info("NIP-17 Receiver: polling " + targetRelays.size() + " relays for pubkey " + recipientPubKeyHex.substring(0, 8) + "... (since " + since + ")");

        List<CompletableFuture<Void>> futures = new ArrayList<>();
        for(String relay : targetRelays) {
            futures.add(CompletableFuture.runAsync(() -> {
                try {
                    List<String> events = queryGiftWraps(relay, since);
                    log.info("NIP-17 Receiver: " + relay + " returned " + events.size() + " gift wrap(s)");
                    for(String eventJson : events) {
                        String eventId = extractField(eventJson, "id");
                        if(eventId != null && seenEvents.add(eventId)) {
                            SilentPaymentNotification notif = decryptGiftWrap(eventJson);
                            if(notif != null) {
                                notifications.add(notif);
                                log.info("NIP-17 Receiver: decoded SP notification: " + notif.amount() + " sats, txid " + notif.txid().substring(0, 8) + "...");
                            } else {
                                log.info("NIP-17 Receiver: gift wrap decrypted but not an SP notification");
                            }
                        }
                    }
                } catch(Exception e) {
                    log.debug("NIP-17 Receiver: failed to poll " + relay + ": " + e.getMessage());
                }
                }
            }));
        }

        try {
            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                    .get(RELAY_TIMEOUT.toMillis() * 2, TimeUnit.MILLISECONDS);
        } catch(Exception e) {
            log.info("NIP-17 Receiver: some relays timed out during notification poll");
        }

        return notifications;
    }

    /**
     * Decrypt a gift wrap event to extract an SP notification.
     * Returns null if decryption fails or content is not an SP notification.
     */
    SilentPaymentNotification decryptGiftWrap(String giftWrapJson) {
        try {
            // Extract gift wrap fields
            String wrapPubkey = extractField(giftWrapJson, "pubkey");
            String wrapContent = extractContentField(giftWrapJson);
            if(wrapPubkey == null || wrapContent == null) return null;

            // Decrypt gift wrap → seal (using delegate — local key or bunker)
            String sealJson = decryptFn.decrypt(wrapPubkey, wrapContent);

            // Extract seal fields
            String sealPubkey = extractField(sealJson, "pubkey");
            String sealContent = extractContentField(sealJson);
            Matcher kindMatcher = KIND_PATTERN.matcher(sealJson);
            if(!kindMatcher.find() || Integer.parseInt(kindMatcher.group(1)) != 13) {
                return null; // Not a seal
            }
            if(sealPubkey == null || sealContent == null) return null;

            // Decrypt seal → rumor (using delegate)
            String rumorJson = decryptFn.decrypt(sealPubkey, sealContent);

            // Extract rumor content
            Matcher rumorKindMatcher = KIND_PATTERN.matcher(rumorJson);
            if(!rumorKindMatcher.find() || Integer.parseInt(rumorKindMatcher.group(1)) != 14) {
                return null; // Not a DM rumor
            }

            String rumorContent = extractDecodedContent(rumorJson);
            if(rumorContent == null) return null;

            // Parse as SP notification
            return SilentPaymentNotification.fromJson(rumorContent);
        } catch(Exception e) {
            log.info("NIP-17 Receiver: failed to decrypt gift wrap: " + e.getMessage());
            return null;
        }
    }

    /**
     * Query a relay for kind 1059 events tagged to our pubkey.
     */
    private List<String> queryGiftWraps(String relayUrl, long since) throws Exception {
        String subscriptionId = UUID.randomUUID().toString().substring(0, 8);
        StringBuilder filter = new StringBuilder();
        filter.append("{\"kinds\":[").append(KIND_GIFT_WRAP).append("],\"#p\":[\"").append(recipientPubKeyHex).append("\"]");
        if(since > 0) {
            filter.append(",\"since\":").append(since);
        }
        filter.append(",\"limit\":50}");

        String reqMessage = "[\"REQ\",\"" + subscriptionId + "\"," + filter + "]";
        String closeMessage = "[\"CLOSE\",\"" + subscriptionId + "\"]";
        log.info("NIP-17 Receiver: querying " + relayUrl + " for kind " + KIND_GIFT_WRAP + " #p=" + recipientPubKeyHex.substring(0, 8) + "...");

        List<String> events = Collections.synchronizedList(new ArrayList<>());
        CompletableFuture<List<String>> resultFuture = new CompletableFuture<>();

        HttpClient client = HttpClient.newBuilder().connectTimeout(RELAY_TIMEOUT).build();
        StringBuilder messageBuffer = new StringBuilder();

        WebSocket webSocket = client.newWebSocketBuilder()
                .connectTimeout(RELAY_TIMEOUT)
                .buildAsync(URI.create(relayUrl), new WebSocket.Listener() {
                    @Override
                    public void onOpen(WebSocket webSocket) {
                        log.info("NIP-17 Receiver: connected to " + relayUrl + ", sending REQ");
                        webSocket.sendText(reqMessage, true);
                        webSocket.request(1);
                    }

                    @Override
                    public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
                        messageBuffer.append(data);
                        if(last) {
                            String message = messageBuffer.toString();
                            messageBuffer.setLength(0);
                            if(message.startsWith("[\"EVENT\"")) {
                                log.info("NIP-17 Receiver: got EVENT from " + relayUrl);
                                String eventObj = extractEventObject(message);
                                if(eventObj != null) {
                                    events.add(eventObj);
                                }
                            } else if(message.startsWith("[\"EOSE\"")) {
                                log.info("NIP-17 Receiver: EOSE from " + relayUrl + " — " + events.size() + " event(s)");
                                resultFuture.complete(events);
                            } else {
                                log.info("NIP-17 Receiver: " + relayUrl + " says: " + message.substring(0, Math.min(80, message.length())));
                            }
                        }
                        webSocket.request(1);
                        return null;
                    }

                    @Override
                    public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
                        if(!resultFuture.isDone()) resultFuture.complete(events);
                        return null;
                    }

                    @Override
                    public void onError(WebSocket webSocket, Throwable error) {
                        if(!resultFuture.isDone()) resultFuture.complete(events);
                    }
                }).join();

        try {
            List<String> result = resultFuture.get(RELAY_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
            webSocket.sendText(closeMessage, true);
            webSocket.sendClose(WebSocket.NORMAL_CLOSURE, "done");
            return result;
        } catch(Exception e) {
            try { webSocket.sendClose(WebSocket.NORMAL_CLOSURE, "timeout"); } catch(Exception ignored) {}
            return events;
        }
    }

    private String extractField(String json, String field) {
        Pattern pattern = Pattern.compile("\"" + field + "\"\\s*:\\s*\"([^\"]+)\"");
        Matcher matcher = pattern.matcher(json);
        return matcher.find() ? matcher.group(1) : null;
    }

    private String extractContentField(String json) {
        Matcher matcher = CONTENT_PATTERN.matcher(json);
        return matcher.find() ? matcher.group(1).replace("\\\"", "\"").replace("\\\\", "\\") : null;
    }

    private String extractDecodedContent(String json) {
        int idx = json.indexOf("\"content\"");
        if(idx < 0) return null;
        int colonIdx = json.indexOf(':', idx + 9);
        if(colonIdx < 0) return null;
        int start = colonIdx + 1;
        while(start < json.length() && json.charAt(start) == ' ') start++;
        if(start >= json.length() || json.charAt(start) != '"') return null;

        StringBuilder content = new StringBuilder();
        boolean escaped = false;
        for(int i = start + 1; i < json.length(); i++) {
            char c = json.charAt(i);
            if(escaped) {
                switch(c) {
                    case '"': content.append('"'); break;
                    case '\\': content.append('\\'); break;
                    case 'n': content.append('\n'); break;
                    case 'r': content.append('\r'); break;
                    case 't': content.append('\t'); break;
                    default: content.append(c);
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

    private String extractEventObject(String message) {
        int braceStart = message.indexOf('{');
        if(braceStart < 0) return null;
        int depth = 0;
        boolean inString = false;
        boolean escaped = false;
        for(int i = braceStart; i < message.length(); i++) {
            char c = message.charAt(i);
            if(escaped) { escaped = false; continue; }
            if(c == '\\' && inString) { escaped = true; continue; }
            if(c == '"') { inString = !inString; continue; }
            if(!inString) {
                if(c == '{') depth++;
                else if(c == '}') {
                    depth--;
                    if(depth == 0) return message.substring(braceStart, i + 1);
                }
            }
        }
        return null;
    }
}
