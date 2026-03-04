package com.sparrowwallet.drongo.nip05;

import com.sparrowwallet.drongo.silentpayments.SilentPaymentAddress;

/**
 * Represents a resolved NIP-05 payment — a Nostr identity that maps to a Silent Payment address.
 *
 * @param hrn the human-readable name (user@domain)
 * @param spAddress the resolved Silent Payment address from the kind 0 profile
 * @param nostrPubkey the hex-encoded Nostr public key
 * @param signatureVerified true if the Nostr event's Schnorr signature was cryptographically verified
 */
public record Nip05Payment(String hrn, SilentPaymentAddress spAddress, String nostrPubkey, boolean signatureVerified) {
    @Override
    public String toString() {
        return "⚡" + hrn;
    }

    public boolean hasSilentPaymentAddress() {
        return spAddress != null;
    }
}
