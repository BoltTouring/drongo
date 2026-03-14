package com.sparrowwallet.drongo.nip05;

/**
 * Represents a Silent Payment notification sent from sender to recipient
 * via NIP-17 encrypted DM after broadcasting the transaction.
 *
 * Contains everything the recipient needs to claim the UTXO without scanning
 * the blockchain: the txid to fetch the transaction, the output index, and
 * the amount. With the txid, the recipient's wallet can extract the sender's
 * input public keys, compute the ECDH shared secret with their scan key,
 * derive the tweak, and compute the spending private key.
 *
 * @param txid transaction ID (64-char hex)
 * @param vout output index in the transaction
 * @param amount value in satoshis
 */
public record SilentPaymentNotification(String txid, int vout, long amount) {

    private static final String TYPE = "silent-payment-notification";
    private static final String VERSION = "1";

    /**
     * Verification status for UI display.
     */
    public enum VerificationStatus {
        UNVERIFIED, VERIFYING, VERIFIED, FAILED
    }

    /**
     * Mutable wrapper for UI — holds immutable notification + verification state.
     */
    public static class Verifiable {
        private final SilentPaymentNotification notification;
        private VerificationStatus status = VerificationStatus.UNVERIFIED;
        private String error;

        public Verifiable(SilentPaymentNotification notification) {
            this.notification = notification;
        }

        public String txid() { return notification.txid(); }
        public int vout() { return notification.vout(); }
        public long amount() { return notification.amount(); }
        public SilentPaymentNotification notification() { return notification; }
        public VerificationStatus verificationStatus() { return status; }
        public String error() { return error; }
        public void setStatus(VerificationStatus status) { this.status = status; }
        public void setError(String error) { this.error = error; }
    }

    /**
     * Serialize to JSON for inclusion in a NIP-17 DM.
     */
    public String toJson() {
        return "{" +
                "\"type\":\"" + TYPE + "\"," +
                "\"version\":\"" + VERSION + "\"," +
                "\"txid\":\"" + txid + "\"," +
                "\"vout\":" + vout + "," +
                "\"amount\":" + amount +
                "}";
    }

    /**
     * Parse from JSON content of a NIP-17 DM.
     * Returns null if the content is not a valid SP notification.
     */
    public static SilentPaymentNotification fromJson(String json) {
        if(json == null || !json.contains("\"" + TYPE + "\"")) {
            return null;
        }

        try {
            String txid = extractStringField(json, "txid");
            int vout = extractIntField(json, "vout");
            long amount = extractLongField(json, "amount");

            if(txid == null || txid.length() != 64) {
                return null;
            }

            return new SilentPaymentNotification(txid, vout, amount);
        } catch(Exception e) {
            return null;
        }
    }

    private static String extractStringField(String json, String field) {
        int idx = json.indexOf("\"" + field + "\"");
        if(idx < 0) return null;
        int colonIdx = json.indexOf(':', idx + field.length() + 2);
        if(colonIdx < 0) return null;
        int startQuote = json.indexOf('"', colonIdx + 1);
        if(startQuote < 0) return null;
        int endQuote = json.indexOf('"', startQuote + 1);
        if(endQuote < 0) return null;
        return json.substring(startQuote + 1, endQuote);
    }

    private static int extractIntField(String json, String field) {
        String value = extractNumericField(json, field);
        return value != null ? Integer.parseInt(value) : 0;
    }

    private static long extractLongField(String json, String field) {
        String value = extractNumericField(json, field);
        return value != null ? Long.parseLong(value) : 0;
    }

    private static String extractNumericField(String json, String field) {
        int idx = json.indexOf("\"" + field + "\"");
        if(idx < 0) return null;
        int colonIdx = json.indexOf(':', idx + field.length() + 2);
        if(colonIdx < 0) return null;
        int start = colonIdx + 1;
        while(start < json.length() && json.charAt(start) == ' ') start++;
        int end = start;
        while(end < json.length() && (Character.isDigit(json.charAt(end)) || json.charAt(end) == '-')) end++;
        return json.substring(start, end);
    }
}
