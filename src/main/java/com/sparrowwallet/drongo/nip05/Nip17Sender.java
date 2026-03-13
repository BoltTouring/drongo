package com.sparrowwallet.drongo.nip05;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.crypto.SchnorrSignature;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeUnit;

/**
 * Sends NIP-17 gift-wrapped direct messages via Nostr relays.
 *
 * NIP-17 flow:
 * 1. Create a "rumor" (unsigned kind 14 event) with the message content
 * 2. Create a "seal" (kind 13): encrypt the rumor to the recipient, sign with sender key
 * 3. Create a "gift wrap" (kind 1059): encrypt the seal with an ephemeral key, tag the recipient
 * 4. Send the gift wrap to the recipient's relays
 *
 * This provides strong metadata protection: relays can't see who sent the message,
 * and the created_at is randomized to prevent timing analysis.
 */
public class Nip17Sender {
    private static final Logger log = LoggerFactory.getLogger(Nip17Sender.class);

    private static final Duration RELAY_TIMEOUT = Duration.ofSeconds(10);
    private static final int KIND_DM = 14;       // NIP-17 DM rumor
    private static final int KIND_SEAL = 13;      // NIP-59 seal
    private static final int KIND_GIFT_WRAP = 1059; // NIP-59 gift wrap

    private static final List<String> DEFAULT_RELAYS = List.of(
            "wss://relay.damus.io",
            "wss://nos.lol",
            "wss://relay.nostr.band"
    );

    private final byte[] senderPrivKey;  // 32-byte secp256k1 private key
    private final String senderPubKeyHex; // 64-char hex public key (x-only)

    public Nip17Sender(byte[] senderPrivKey) {
        this.senderPrivKey = senderPrivKey;
        ECKey key = ECKey.fromPrivate(senderPrivKey);
        this.senderPubKeyHex = Utils.bytesToHex(key.getPubKeyXCoord());
    }

    /**
     * Send a Silent Payment notification to a recipient via NIP-17.
     *
     * @param recipientPubKeyHex recipient's 64-char hex public key
     * @param notification the SP notification to send
     * @param relays relay URLs to publish to (uses defaults if null)
     */
    public void sendNotification(String recipientPubKeyHex, SilentPaymentNotification notification, List<String> relays) {
        String content = notification.toJson();
        List<String> targetRelays = relays != null ? relays : DEFAULT_RELAYS;

        try {
            String giftWrapJson = createGiftWrap(recipientPubKeyHex, content);

            for(String relay : targetRelays) {
                try {
                    publishEvent(relay, giftWrapJson);
                    log.info("SP notification sent to " + relay + " for recipient " + recipientPubKeyHex.substring(0, 8) + "...");
                } catch(Exception e) {
                    log.warn("Failed to send SP notification to " + relay + ": " + e.getMessage());
                }
            }
        } catch(Exception e) {
            log.error("Failed to create gift wrap for SP notification", e);
        }
    }

    /**
     * Create the full gift-wrapped event JSON.
     */
    String createGiftWrap(String recipientPubKeyHex, String content) {
        SecureRandom random = new SecureRandom();

        // Step 1: Create rumor (unsigned kind 14)
        long rumorCreatedAt = System.currentTimeMillis() / 1000;
        String rumorJson = createEventJson("", rumorCreatedAt, KIND_DM, content,
                "[[\"p\",\"" + recipientPubKeyHex + "\"]]");

        // Step 2: Create seal (kind 13) — encrypt rumor to recipient, sign with sender key
        byte[] recipientPubKey33 = pubKeyHexToCompressed(recipientPubKeyHex);
        String encryptedRumor = Nip44.encrypt(senderPrivKey, recipientPubKey33, rumorJson);

        // Seal created_at is randomized ±48h
        long sealCreatedAt = rumorCreatedAt + (random.nextInt(172800) - 86400);
        String sealUnsigned = createEventJson(senderPubKeyHex, sealCreatedAt, KIND_SEAL, encryptedRumor, "[]");
        String sealSigned = signEvent(sealUnsigned, senderPrivKey);

        // Step 3: Create gift wrap (kind 1059) — encrypt seal with ephemeral key
        byte[] ephemeralPrivKey = new byte[32];
        random.nextBytes(ephemeralPrivKey);
        // Ensure valid private key
        while(new java.math.BigInteger(1, ephemeralPrivKey).compareTo(ECKey.CURVE.getCurve().getOrder()) >= 0
                || new java.math.BigInteger(1, ephemeralPrivKey).equals(java.math.BigInteger.ZERO)) {
            random.nextBytes(ephemeralPrivKey);
        }
        ECKey ephemeralKey = ECKey.fromPrivate(ephemeralPrivKey);
        String ephemeralPubKeyHex = Utils.bytesToHex(ephemeralKey.getPubKeyXCoord());

        String encryptedSeal = Nip44.encrypt(ephemeralPrivKey, recipientPubKey33, sealSigned);

        // Gift wrap created_at also randomized
        long wrapCreatedAt = rumorCreatedAt + (random.nextInt(172800) - 86400);
        String wrapTags = "[[\"p\",\"" + recipientPubKeyHex + "\"]]";
        String wrapUnsigned = createEventJson(ephemeralPubKeyHex, wrapCreatedAt, KIND_GIFT_WRAP, encryptedSeal, wrapTags);
        return signEvent(wrapUnsigned, ephemeralPrivKey);
    }

    /**
     * Create a Nostr event JSON string (without id and sig).
     */
    private String createEventJson(String pubkey, long createdAt, int kind, String content, String tagsJson) {
        String escapedContent = escapeJsonString(content);
        return "{\"pubkey\":\"" + pubkey + "\",\"created_at\":" + createdAt +
                ",\"kind\":" + kind + ",\"tags\":" + tagsJson +
                ",\"content\":\"" + escapedContent + "\"}";
    }

    /**
     * Compute event ID and sign with Schnorr. Returns the complete signed event JSON.
     */
    private String signEvent(String eventJson, byte[] privateKey) {
        // Extract fields for serialization
        String pubkey = extractField(eventJson, "pubkey");
        String createdAt = extractField(eventJson, "created_at");
        String kind = extractField(eventJson, "kind");
        String tags = extractTagsJson(eventJson);
        String content = extractContentRaw(eventJson);

        // NIP-01 serialization: [0, pubkey, created_at, kind, tags, content]
        String serialized = "[0,\"" + pubkey + "\"," + createdAt + "," + kind + "," + tags + "," + content + "]";

        // SHA-256 hash → event ID
        byte[] hash = Sha256Hash.hash(serialized.getBytes(StandardCharsets.UTF_8));
        String id = Utils.bytesToHex(hash);

        // Schnorr sign
        ECKey key = ECKey.fromPrivate(privateKey);
        SchnorrSignature sig = key.signSchnorr(Sha256Hash.wrap(hash));
        String sigHex = Utils.bytesToHex(sig.encode());

        return "{\"id\":\"" + id + "\",\"pubkey\":\"" + pubkey +
                "\",\"created_at\":" + createdAt + ",\"kind\":" + kind +
                ",\"tags\":" + tags + ",\"content\":" + content +
                ",\"sig\":\"" + sigHex + "\"}";
    }

    /**
     * Publish an event to a relay via WebSocket.
     */
    private void publishEvent(String relayUrl, String eventJson) throws Exception {
        String message = "[\"EVENT\"," + eventJson + "]";
        CompletableFuture<Boolean> result = new CompletableFuture<>();

        HttpClient client = HttpClient.newBuilder().connectTimeout(RELAY_TIMEOUT).build();

        WebSocket webSocket = client.newWebSocketBuilder()
                .connectTimeout(RELAY_TIMEOUT)
                .buildAsync(URI.create(relayUrl), new WebSocket.Listener() {
                    @Override
                    public void onOpen(WebSocket webSocket) {
                        webSocket.sendText(message, true);
                        webSocket.request(1);
                    }

                    @Override
                    public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
                        String response = data.toString();
                        if(response.startsWith("[\"OK\"")) {
                            log.info("NIP-17 Sender: relay response from " + relayUrl + ": " + response.substring(0, Math.min(150, response.length())));
                            result.complete(response.contains("true"));
                        } else if(response.startsWith("[\"NOTICE\"")) {
                            log.warn("NIP-17 Sender: relay notice from " + relayUrl + ": " + response);
                            result.complete(false);
                        } else {
                            log.info("NIP-17 Sender: relay says: " + response.substring(0, Math.min(100, response.length())));
                        }
                        webSocket.request(1);
                        return null;
                    }

                    @Override
                    public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
                        if(!result.isDone()) result.complete(false);
                        return null;
                    }

                    @Override
                    public void onError(WebSocket webSocket, Throwable error) {
                        if(!result.isDone()) result.completeExceptionally(error);
                    }
                }).join();

        try {
            result.get(RELAY_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
        } finally {
            try {
                webSocket.sendClose(WebSocket.NORMAL_CLOSURE, "done");
            } catch(Exception ignored) {}
        }
    }

    /**
     * Convert a 64-char hex x-only pubkey to a 33-byte compressed pubkey (02 prefix).
     */
    static byte[] pubKeyHexToCompressed(String hexPubKey) {
        byte[] xOnly = Utils.hexToBytes(hexPubKey);
        byte[] compressed = new byte[33];
        compressed[0] = 0x02;
        System.arraycopy(xOnly, 0, compressed, 1, 32);
        return compressed;
    }

    private String extractField(String json, String field) {
        int idx = json.indexOf("\"" + field + "\"");
        if(idx < 0) return "";
        int colonIdx = json.indexOf(':', idx);
        if(colonIdx < 0) return "";
        int start = colonIdx + 1;
        while(start < json.length() && json.charAt(start) == ' ') start++;
        if(json.charAt(start) == '"') {
            int end = json.indexOf('"', start + 1);
            return json.substring(start + 1, end);
        } else {
            int end = start;
            while(end < json.length() && json.charAt(end) != ',' && json.charAt(end) != '}') end++;
            return json.substring(start, end).trim();
        }
    }

    private String extractTagsJson(String json) {
        int idx = json.indexOf("\"tags\"");
        if(idx < 0) return "[]";
        int colonIdx = json.indexOf(':', idx);
        if(colonIdx < 0) return "[]";
        int start = colonIdx + 1;
        while(start < json.length() && json.charAt(start) == ' ') start++;
        int depth = 0;
        for(int i = start; i < json.length(); i++) {
            char c = json.charAt(i);
            if(c == '[') depth++;
            else if(c == ']') {
                depth--;
                if(depth == 0) return json.substring(start, i + 1);
            }
        }
        return "[]";
    }

    private String extractContentRaw(String json) {
        int idx = json.indexOf("\"content\"");
        if(idx < 0) return "\"\"";
        int colonIdx = json.indexOf(':', idx);
        if(colonIdx < 0) return "\"\"";
        int start = colonIdx + 1;
        while(start < json.length() && json.charAt(start) == ' ') start++;
        if(json.charAt(start) != '"') return "\"\"";
        boolean escaped = false;
        for(int i = start + 1; i < json.length(); i++) {
            char c = json.charAt(i);
            if(escaped) { escaped = false; continue; }
            if(c == '\\') { escaped = true; continue; }
            if(c == '"') return json.substring(start, i + 1);
        }
        return "\"\"";
    }

    private static String escapeJsonString(String s) {
        StringBuilder sb = new StringBuilder();
        for(int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch(c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if(c < 0x20) {
                        sb.append(String.format("\\u%04x", (int)c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }
}
