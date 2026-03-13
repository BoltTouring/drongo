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
import java.net.URLEncoder;
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
    private static final Duration TIMEOUT = Duration.ofSeconds(30);
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(90);
    private static final String DEFAULT_RELAY = "wss://relay.nsec.app";

    private String signerPubKeyHex; // null until signer connects (nostrconnect flow)
    private final String relayUrl;
    private final String secret;
    private final byte[] localPrivKey;
    private final String localPubKeyHex;
    private final boolean isNostrConnectFlow;

    private WebSocket webSocket;
    private final Map<String, CompletableFuture<String>> pendingRequests = new ConcurrentHashMap<>();
    private final CompletableFuture<String> signerConnected = new CompletableFuture<>();
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

        return new Nip46BunkerClient(pubkey, relay, secret, false);
    }

    /**
     * Create a client for the nostrconnect:// flow.
     * Generates a random secret that the signer must return to prove connection.
     */
    public static Nip46BunkerClient forNostrConnect(String relayUrl) {
        // Generate a random secret for connection validation
        byte[] secretBytes = new byte[16];
        new SecureRandom().nextBytes(secretBytes);
        String connectSecret = Utils.bytesToHex(secretBytes);
        return new Nip46BunkerClient(null, relayUrl != null ? relayUrl : DEFAULT_RELAY, connectSecret, true);
    }

    /**
     * Generate a nostrconnect:// URI for pasting into nsec.app or Amber.
     * Includes required secret parameter per NIP-46 spec.
     */
    public String getNostrConnectUri() {
        String uri = "nostrconnect://" + localPubKeyHex + "?relay=" +
                URLEncoder.encode(relayUrl, StandardCharsets.UTF_8) +
                "&metadata=" + URLEncoder.encode("{\"name\":\"Sparrow Wallet\",\"description\":\"Silent Payment notifications\",\"url\":\"https://sparrowwallet.com\"}", StandardCharsets.UTF_8) +
                "&perms=nip44_decrypt,nip44_encrypt,get_public_key";
        if(secret != null) {
            uri += "&secret=" + secret;
        }
        return uri;
    }

    private Nip46BunkerClient(String signerPubKeyHex, String relayUrl, String secret, boolean isNostrConnectFlow) {
        this.signerPubKeyHex = signerPubKeyHex;
        this.relayUrl = relayUrl;
        this.secret = secret;
        this.isNostrConnectFlow = isNostrConnectFlow;

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
     * Start listening on the relay for incoming events.
     * Call this early (before showing the URI to the user) to avoid missing the signer's response.
     */
    public void startListening() {
        if(webSocket != null) return; // Already listening

        Thread.ofVirtual().start(() -> {
            try {
                openWebSocket();
                log.info("NIP-46: pre-connected and listening on " + relayUrl);
            } catch(Exception e) {
                log.error("NIP-46: failed to pre-connect: " + e.getMessage());
            }
        });
    }

    private void openWebSocket() throws Exception {
        if(webSocket != null) return;

        String subscriptionId = UUID.randomUUID().toString().substring(0, 8);
        long since = (System.currentTimeMillis() / 1000) - 120; // Catch events from last 2 minutes
        String subMessage = "[\"REQ\",\"" + subscriptionId + "\",{\"kinds\":[" + KIND_NIP46_REQUEST + "],\"#p\":[\"" + localPubKeyHex + "\"],\"since\":" + since + "}]";

        CompletableFuture<Void> connected = new CompletableFuture<>();

        HttpClient client = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();
        webSocket = client.newWebSocketBuilder()
                .connectTimeout(TIMEOUT)
                .buildAsync(URI.create(relayUrl), new WebSocket.Listener() {
                    @Override
                    public void onOpen(WebSocket ws) {
                        log.info("NIP-46: WebSocket connected to " + relayUrl);
                        log.info("NIP-46: subscribing for kind " + KIND_NIP46_REQUEST + " tagged to " + localPubKeyHex.substring(0, 8) + "...");
                        ws.sendText(subMessage, true);
                        connected.complete(null);
                        ws.request(1);
                    }

                    @Override
                    public CompletionStage<?> onText(WebSocket ws, CharSequence data, boolean last) {
                        messageBuffer.append(data);
                        if(last) {
                            String msg = messageBuffer.toString();
                            if(msg.startsWith("[\"EVENT\"")) {
                                log.info("NIP-46: relay event received (" + msg.length() + " chars)");
                            } else if(msg.startsWith("[\"OK\"")) {
                                log.info("NIP-46: relay OK: " + msg.substring(0, Math.min(120, msg.length())));
                            } else if(msg.startsWith("[\"EOSE\"")) {
                                log.info("NIP-46: relay EOSE — subscription active");
                            } else if(msg.startsWith("[\"NOTICE\"")) {
                                log.warn("NIP-46: relay notice: " + msg);
                            } else if(msg.startsWith("[\"AUTH\"")) {
                                log.info("NIP-46: relay AUTH challenge received");
                                handleAuth(ws, msg);
                            } else {
                                log.info("NIP-46: relay message: " + msg.substring(0, Math.min(120, msg.length())));
                            }
                            handleMessage(msg);
                            messageBuffer.setLength(0);
                        }
                        ws.request(1);
                        return null;
                    }

                    @Override
                    public CompletionStage<?> onClose(WebSocket ws, int code, String reason) {
                        log.info("NIP-46: WebSocket closed: " + reason);
                        pendingRequests.values().forEach(f -> f.completeExceptionally(new Exception("Connection closed")));
                        return null;
                    }

                    @Override
                    public void onError(WebSocket ws, Throwable error) {
                        log.error("NIP-46: WebSocket error: " + error.getMessage());
                        pendingRequests.values().forEach(f -> f.completeExceptionally(error));
                    }
                }).join();

        connected.get(TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
    }

    /**
     * Connect to the bunker relay and establish a session with the signer.
     */
    public void connect() throws Exception {
        openWebSocket();

        if(isNostrConnectFlow) {
            // nostrconnect flow: wait for signer to connect to us
            log.info("NIP-46: waiting for signer to connect via nostrconnect (relay: " + relayUrl + ", timeout: " + CONNECT_TIMEOUT.toSeconds() + "s)...");
            log.info("NIP-46: nostrconnect URI has secret: " + (secret != null));
            try {
                String signerPubKey = signerConnected.get(CONNECT_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
                this.signerPubKeyHex = signerPubKey;
                log.info("NIP-46: signer connected successfully: " + signerPubKey.substring(0, 8) + "...");
            } catch(TimeoutException e) {
                throw new Exception("Timed out waiting for signer — did you paste the nostrconnect URI into your bunker app?");
            }
        } else {
            // bunker:// flow: send connect request to signer
            String connectParams;
            if(secret != null) {
                connectParams = "[\"" + signerPubKeyHex + "\",\"" + secret + "\"]";
            } else {
                connectParams = "[\"" + signerPubKeyHex + "\"]";
            }
            sendRequest("connect", connectParams, CONNECT_TIMEOUT);
            log.info("Connected to bunker at " + relayUrl + " (signer: " + signerPubKeyHex.substring(0, 8) + "...)");
        }
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
        if(signerPubKeyHex != null) {
            return signerPubKeyHex;
        }
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

    /**
     * Handle NIP-42 AUTH challenge from relay.
     * Signs a kind 22242 event with the challenge and relay URL, sends it back.
     */
    private void handleAuth(WebSocket ws, String authMessage) {
        try {
            // Extract challenge from ["AUTH","<challenge>"]
            // Find 3rd and 4th quotes in the message
            int q = -1;
            for(int i = 0; i < 3; i++) {
                q = authMessage.indexOf('"', q + 1);
                if(q < 0) { log.warn("NIP-46: malformed AUTH (quote " + i + ")"); return; }
            }
            int challengeStart = q + 1;
            int challengeEnd = authMessage.indexOf('"', challengeStart);
            if(challengeEnd < 0) { log.warn("NIP-46: malformed AUTH (no closing quote)"); return; }
            String challenge = authMessage.substring(challengeStart, challengeEnd);
            log.info("NIP-46: AUTH challenge: " + challenge);

            // Build kind 22242 AUTH event
            long createdAt = System.currentTimeMillis() / 1000;
            String tags = "[[\"relay\",\"" + escapeJson(relayUrl) + "\"],[\"challenge\",\"" + escapeJson(challenge) + "\"]]";
            String serialized = "[0,\"" + localPubKeyHex + "\"," + createdAt + ",22242," + tags + ",\"\"]";

            byte[] hash = Sha256Hash.hash(serialized.getBytes(StandardCharsets.UTF_8));
            String id = Utils.bytesToHex(hash);
            ECKey key = ECKey.fromPrivate(localPrivKey);
            SchnorrSignature sig = key.signSchnorr(Sha256Hash.wrap(hash));
            String sigHex = Utils.bytesToHex(sig.encode());

            String authEvent = "{\"id\":\"" + id + "\",\"pubkey\":\"" + localPubKeyHex +
                    "\",\"created_at\":" + createdAt + ",\"kind\":22242,\"tags\":" + tags +
                    ",\"content\":\"\",\"sig\":\"" + sigHex + "\"}";

            ws.sendText("[\"AUTH\"," + authEvent + "]", true);
            log.info("NIP-46: AUTH response sent");

            // Re-send subscription after AUTH (relay may have ignored it before auth)
            String subscriptionId = UUID.randomUUID().toString().substring(0, 8);
            long since = (System.currentTimeMillis() / 1000) - 120;
            String subMessage = "[\"REQ\",\"" + subscriptionId + "\",{\"kinds\":[" + KIND_NIP46_REQUEST + "],\"#p\":[\"" + localPubKeyHex + "\"],\"since\":" + since + "}]";
            ws.sendText(subMessage, true);
            log.info("NIP-46: re-subscribed after AUTH");
        } catch(Exception e) {
            log.error("NIP-46: AUTH handling failed: " + e.getMessage(), e);
        }
    }

    private void handleMessage(String message) {
        if(!message.startsWith("[\"EVENT\"")) return;

        try {
            int braceStart = message.indexOf('{');
            if(braceStart < 0) return;
            String eventJson = extractEventObject(message, braceStart);
            if(eventJson == null) return;

            // Extract sender pubkey
            Pattern pubkeyPattern = Pattern.compile("\"pubkey\"\\s*:\\s*\"([0-9a-f]{64})\"");
            Matcher pkMatcher = pubkeyPattern.matcher(eventJson);
            if(!pkMatcher.find()) return;
            String eventPubkey = pkMatcher.group(1);
            log.info("NIP-46: received event from " + eventPubkey.substring(0, 8) + "...");

            // For bunker:// flow, verify it's from the expected signer
            if(!isNostrConnectFlow && signerPubKeyHex != null && !eventPubkey.equals(signerPubKeyHex)) {
                log.debug("NIP-46: ignoring event from unexpected pubkey");
                return;
            }

            // Extract and unescape content
            String encryptedContent = extractContentFromEvent(eventJson);
            if(encryptedContent == null) {
                log.warn("NIP-46: could not extract content from event");
                return;
            }
            log.info("NIP-46: decrypting content (" + encryptedContent.length() + " chars)");

            // Decrypt content
            byte[] senderPubKey33 = Nip17Sender.pubKeyHexToCompressed(eventPubkey);
            String rpcResponse;
            try {
                rpcResponse = Nip44.decrypt(localPrivKey, senderPubKey33, encryptedContent);
            } catch(Exception decryptEx) {
                log.error("NIP-46: decryption failed: " + decryptEx.getMessage());
                // For nostrconnect flow, still record the signer even if decrypt fails
                if(isNostrConnectFlow && !signerConnected.isDone()) {
                    log.info("NIP-46: signer detected despite decrypt failure: " + eventPubkey.substring(0, 8) + "...");
                }
                return;
            }
            log.info("NIP-46: decrypted response: " + rpcResponse.substring(0, Math.min(100, rpcResponse.length())) + "...");

            // For nostrconnect flow: any successfully decrypted message means signer connected
            if(isNostrConnectFlow && !signerConnected.isDone()) {
                signerPubKeyHex = eventPubkey;
                signerConnected.complete(eventPubkey);
                log.info("NIP-46: signer connected: " + eventPubkey.substring(0, 8) + "...");
            }

            // Parse JSON-RPC response — extract id
            Pattern idPattern = Pattern.compile("\"id\"\\s*:\\s*\"([^\"]+)\"");
            Matcher idMatcher = idPattern.matcher(rpcResponse);
            if(!idMatcher.find()) {
                log.debug("NIP-46: no id in response, ignoring for request matching");
                return;
            }
            String responseId = idMatcher.group(1);

            CompletableFuture<String> future = pendingRequests.remove(responseId);
            if(future == null) {
                log.debug("NIP-46: no pending request for id " + responseId);
                return;
            }

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
            log.error("NIP-46: error handling message: " + e.getMessage(), e);
        }
    }

    /**
     * Extract and unescape the content field from a Nostr event JSON.
     * Uses character-by-character parsing instead of regex to handle all escape sequences.
     */
    private String extractContentFromEvent(String json) {
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
                    case '/': content.append('/'); break;
                    default: content.append('\\'); content.append(c);
                }
                escaped = false;
            } else if(c == '\\') {
                escaped = true;
            } else if(c == '"') {
                return content.toString();
            } else {
                content.append(c);
            }
        }
        return null;
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

    public boolean isSignerConnected() {
        return signerConnected.isDone();
    }

    /**
     * Wait for the signer to connect (for nostrconnect flow).
     * Call startListening() first, then show the URI, then this.
     */
    public void waitForSigner() throws Exception {
        if(signerConnected.isDone()) return;
        log.info("NIP-46: waiting for signer (timeout: " + CONNECT_TIMEOUT.toSeconds() + "s)...");
        try {
            String signerPubKey = signerConnected.get(CONNECT_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
            this.signerPubKeyHex = signerPubKey;
            log.info("NIP-46: signer connected: " + signerPubKey.substring(0, 8) + "...");
        } catch(TimeoutException e) {
            throw new Exception("Timed out waiting for signer — did you paste the nostrconnect URI into your bunker app?");
        }
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
