package com.sparrowwallet.drongo.nip05;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.crypto.SchnorrSignature;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Minimal NIP-46 (Nostr Connect) client for requesting NIP-44 decryption from a remote signer.
 *
 * The user's nsec never touches Sparrow. Instead, the bunker handles all private key operations.
 * This client only supports the "nip44_decrypt" method — enough for receiving SP notifications.
 *
 * Usage:
 *   Nip46BunkerClient bunker = Nip46BunkerClient.fromUri("bunker://pubkey?relay=wss://relay&secret=token");
 *   bunker.connect();
 *   String plaintext = bunker.decrypt(senderPubkeyHex, nip44Ciphertext);
 *   bunker.close();
 */
public class Nip46BunkerClient implements AutoCloseable {
    private static final Logger log = LoggerFactory.getLogger(Nip46BunkerClient.class);

    private static final int KIND_NIP46_REQUEST = 24133;
    private static final Duration TIMEOUT = Duration.ofSeconds(15);
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(90);

    private final String signerPubKeyHex;
    private final String relayUrl;
    private final String secret;
    private final byte[] localPrivKey;
    private final String localPubKeyHex;

    private WebSocket webSocket;
    private final Map<String, CompletableFuture<String>> pendingRequests = new ConcurrentHashMap<>();
    private final StringBuilder messageBuffer = new StringBuilder();

    /**
     * Parse a bunker:// URI.
     * Format: bunker://<hex-pubkey>?relay=wss://relay.example.com&secret=optional_token
     */
    public static Nip46BunkerClient fromUri(String uri) {
        if(!uri.startsWith("bunker://")) {
            throw new IllegalArgumentException("Invalid bunker URI: must start with bunker://");
        }

        String withoutScheme = uri.substring("bunker://".length());
        int queryIdx = withoutScheme.indexOf('?');
        String pubkey = queryIdx > 0 ? withoutScheme.substring(0, queryIdx) : withoutScheme;
        if(pubkey.length() != 64 || !pubkey.matches("[0-9a-f]+")) {
            throw new IllegalArgumentException("Invalid bunker pubkey: " + pubkey);
        }

        String relay = null;
        String secret = null;

        if(queryIdx > 0) {
            String query = withoutScheme.substring(queryIdx + 1);
            for(String param : query.split("&")) {
                String[] kv = param.split("=", 2);
                if(kv.length == 2) {
                    String key = kv[0];
                    String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    if("relay".equals(key)) relay = value;
                    else if("secret".equals(key)) secret = value;
                }
            }
        }

        if(relay == null) {
            throw new IllegalArgumentException("Bunker URI must contain a relay parameter");
        }

        return new Nip46BunkerClient(pubkey, relay, secret);
    }

    private Nip46BunkerClient(String signerPubKeyHex, String relayUrl, String secret) {
        this.signerPubKeyHex = signerPubKeyHex;
        this.relayUrl = relayUrl;
        this.secret = secret;

        // Generate ephemeral local keypair for this session
        SecureRandom random = new SecureRandom();
        this.localPrivKey = new byte[32];
        random.nextBytes(localPrivKey);
        while(new BigInteger(1, localPrivKey).compareTo(ECKey.CURVE.getCurve().getOrder()) >= 0
                || new BigInteger(1, localPrivKey).equals(BigInteger.ZERO)) {
            random.nextBytes(localPrivKey);
        }
        ECKey localKey = ECKey.fromPrivate(localPrivKey);
        this.localPubKeyHex = Utils.bytesToHex(localKey.getPubKeyXCoord());
    }

    /**
     * Connect to the bunker relay and subscribe for responses.
     */
    public void connect() throws Exception {
        String subscriptionId = UUID.randomUUID().toString().substring(0, 8);
        String subMessage = "[\"REQ\",\"" + subscriptionId + "\",{\"kinds\":[" + KIND_NIP46_REQUEST + "],\"#p\":[\"" + localPubKeyHex + "\"],\"limit\":0}]";

        CompletableFuture<Void> connected = new CompletableFuture<>();

        HttpClient client = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();
        webSocket = client.newWebSocketBuilder()
                .connectTimeout(TIMEOUT)
                .buildAsync(URI.create(relayUrl), new WebSocket.Listener() {
                    @Override
                    public void onOpen(WebSocket ws) {
                        ws.sendText(subMessage, true);
                        connected.complete(null);
                        ws.request(1);
                    }

                    @Override
                    public CompletionStage<?> onText(WebSocket ws, CharSequence data, boolean last) {
                        messageBuffer.append(data);
                        if(last) {
                            handleMessage(messageBuffer.toString());
                            messageBuffer.setLength(0);
                        }
                        ws.request(1);
                        return null;
                    }

                    @Override
                    public CompletionStage<?> onClose(WebSocket ws, int code, String reason) {
                        pendingRequests.values().forEach(f -> f.completeExceptionally(new Exception("Connection closed")));
                        return null;
                    }

                    @Override
                    public void onError(WebSocket ws, Throwable error) {
                        pendingRequests.values().forEach(f -> f.completeExceptionally(error));
                    }
                }).join();

        connected.get(TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);

        // Always send connect request — user must approve in their bunker app
        // NIP-46: connect params = [<client_pubkey>, <optional_secret>]
        // The signer needs to know WHO is connecting
        String connectParams;
        if(secret != null) {
            connectParams = "[\"" + localPubKeyHex + "\",\"" + secret + "\"]";
        } else {
            connectParams = "[\"" + localPubKeyHex + "\"]";
        }
        sendRequest("connect", connectParams, CONNECT_TIMEOUT);

        log.info("Connected to bunker at " + relayUrl + " (signer: " + signerPubKeyHex.substring(0, 8) + "...)");
    }

    /**
     * Request NIP-44 decryption from the bunker.
     *
     * @param thirdPartyPubKeyHex the pubkey of the other party (for ECDH)
     * @param ciphertext the NIP-44 base64 ciphertext to decrypt
     * @return the decrypted plaintext
     */
    public String decrypt(String thirdPartyPubKeyHex, String ciphertext) throws Exception {
        String params = "[\"" + thirdPartyPubKeyHex + "\",\"" + escapeJson(ciphertext) + "\"]";
        return sendRequest("nip44_decrypt", params);
    }

    /**
     * Get the public key managed by the bunker.
     */
    public String getPublicKey() throws Exception {
        return sendRequest("get_public_key", "[]");
    }

    private String sendRequest(String method, String paramsJson) throws Exception {
        return sendRequest(method, paramsJson, TIMEOUT);
    }

    private String sendRequest(String method, String paramsJson, Duration timeout) throws Exception {
        String requestId = UUID.randomUUID().toString();
        String rpcJson = "{\"id\":\"" + requestId + "\",\"method\":\"" + method + "\",\"params\":" + paramsJson + "}";

        // Encrypt request to signer with NIP-44
        byte[] signerPubKey33 = Nip17Sender.pubKeyHexToCompressed(signerPubKeyHex);
        String encrypted = Nip44.encrypt(localPrivKey, signerPubKey33, rpcJson);

        // Build and sign the event
        long createdAt = System.currentTimeMillis() / 1000;
        String tags = "[[\"p\",\"" + signerPubKeyHex + "\"]]";
        String serialized = "[0,\"" + localPubKeyHex + "\"," + createdAt + "," + KIND_NIP46_REQUEST + "," + tags + ",\"" + escapeJson(encrypted) + "\"]";

        byte[] hash = Sha256Hash.hash(serialized.getBytes(StandardCharsets.UTF_8));
        String id = Utils.bytesToHex(hash);
        ECKey key = ECKey.fromPrivate(localPrivKey);
        SchnorrSignature sig = key.signSchnorr(Sha256Hash.wrap(hash));
        String sigHex = Utils.bytesToHex(sig.encode());

        String eventJson = "{\"id\":\"" + id + "\",\"pubkey\":\"" + localPubKeyHex + "\",\"created_at\":" + createdAt +
                ",\"kind\":" + KIND_NIP46_REQUEST + ",\"tags\":" + tags + ",\"content\":\"" + escapeJson(encrypted) + "\",\"sig\":\"" + sigHex + "\"}";

        CompletableFuture<String> responseFuture = new CompletableFuture<>();
        pendingRequests.put(requestId, responseFuture);

        webSocket.sendText("[\"EVENT\"," + eventJson + "]", true);

        try {
            return responseFuture.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch(TimeoutException e) {
            pendingRequests.remove(requestId);
            throw new Exception("Bunker request timed out: " + method + " (waited " + timeout.toSeconds() + "s — did you approve in your bunker app?)");
        }
    }

    private void handleMessage(String message) {
        if(!message.startsWith("[\"EVENT\"")) return;

        try {
            // Extract the event object
            int braceStart = message.indexOf('{');
            if(braceStart < 0) return;
            String eventJson = extractEventObject(message, braceStart);
            if(eventJson == null) return;

            // Check it's from the signer
            Pattern pubkeyPattern = Pattern.compile("\"pubkey\"\\s*:\\s*\"([0-9a-f]{64})\"");
            Matcher pkMatcher = pubkeyPattern.matcher(eventJson);
            if(!pkMatcher.find() || !pkMatcher.group(1).equals(signerPubKeyHex)) return;

            // Decrypt content
            Pattern contentPattern = Pattern.compile("\"content\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
            Matcher contentMatcher = contentPattern.matcher(eventJson);
            if(!contentMatcher.find()) return;
            String encryptedContent = contentMatcher.group(1).replace("\\\"", "\"").replace("\\\\", "\\");

            byte[] signerPubKey33 = Nip17Sender.pubKeyHexToCompressed(signerPubKeyHex);
            String rpcResponse = Nip44.decrypt(localPrivKey, signerPubKey33, encryptedContent);

            // Parse JSON-RPC response
            Pattern idPattern = Pattern.compile("\"id\"\\s*:\\s*\"([^\"]+)\"");
            Matcher idMatcher = idPattern.matcher(rpcResponse);
            if(!idMatcher.find()) return;
            String responseId = idMatcher.group(1);

            CompletableFuture<String> future = pendingRequests.remove(responseId);
            if(future == null) return;

            // Check for error
            if(rpcResponse.contains("\"error\"")) {
                Pattern errorPattern = Pattern.compile("\"error\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
                Matcher errorMatcher = errorPattern.matcher(rpcResponse);
                if(errorMatcher.find()) {
                    future.completeExceptionally(new Exception("Bunker error: " + errorMatcher.group(1)));
                    return;
                }
            }

            // Extract result
            Pattern resultPattern = Pattern.compile("\"result\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
            Matcher resultMatcher = resultPattern.matcher(rpcResponse);
            if(resultMatcher.find()) {
                future.complete(resultMatcher.group(1).replace("\\\"", "\"").replace("\\\\", "\\"));
            } else {
                future.complete(rpcResponse);
            }
        } catch(Exception e) {
            log.debug("Error handling bunker response: " + e.getMessage());
        }
    }

    private String extractEventObject(String message, int start) {
        int depth = 0;
        boolean inString = false;
        boolean escaped = false;
        for(int i = start; i < message.length(); i++) {
            char c = message.charAt(i);
            if(escaped) { escaped = false; continue; }
            if(c == '\\' && inString) { escaped = true; continue; }
            if(c == '"') { inString = !inString; continue; }
            if(!inString) {
                if(c == '{') depth++;
                else if(c == '}') {
                    depth--;
                    if(depth == 0) return message.substring(start, i + 1);
                }
            }
        }
        return null;
    }

    @Override
    public void close() {
        if(webSocket != null) {
            try {
                webSocket.sendClose(WebSocket.NORMAL_CLOSURE, "done");
            } catch(Exception ignored) {}
        }
        pendingRequests.values().forEach(f -> f.cancel(true));
        pendingRequests.clear();
        Arrays.fill(localPrivKey, (byte)0);
    }

    public String getSignerPubKeyHex() {
        return signerPubKeyHex;
    }

    private static String escapeJson(String s) {
        StringBuilder sb = new StringBuilder();
        for(int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch(c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default: sb.append(c);
            }
        }
        return sb.toString();
    }
}
