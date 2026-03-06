package com.sparrowwallet.drongo.nip05;

import com.sparrowwallet.drongo.silentpayments.SilentPaymentAddress;

/**
 * Represents a Nostr contact resolved from a kind 3 follow list,
 * with optional Silent Payment address from their kind 0 profile.
 *
 * @param pubkey hex-encoded Nostr public key
 * @param displayName profile name (or abbreviated pubkey if no name set)
 * @param spAddress Silent Payment address from the "sp" profile field, or null
 * @param nip05 NIP-05 identifier (user@domain) if set in profile, or null
 * @param pictureUrl profile picture URL if set, or null
 * @param signatureVerified true if the kind 0 event signature was cryptographically verified
 */
public record NostrContact(String pubkey, String displayName, SilentPaymentAddress spAddress,
                            String nip05, String pictureUrl, boolean signatureVerified) {

    public boolean hasSilentPaymentAddress() {
        return spAddress != null;
    }

    /**
     * Returns the first 8 hex chars of the pubkey followed by "..."
     */
    public String getShortPubkey() {
        if(pubkey == null || pubkey.length() < 8) {
            return pubkey;
        }
        return pubkey.substring(0, 8) + "...";
    }

    /**
     * Returns the best available display string for this contact.
     */
    public String getDisplayString() {
        if(nip05 != null && !nip05.isEmpty()) {
            return displayName + " (" + nip05 + ")";
        }
        return displayName;
    }
}
