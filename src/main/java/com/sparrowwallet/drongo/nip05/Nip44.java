package com.sparrowwallet.drongo.nip05;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * NIP-44 v2 encryption/decryption.
 * Uses secp256k1 ECDH → HKDF-SHA256 → ChaCha20 (plain) → HMAC-SHA256.
 *
 * Reference: https://github.com/nostr-protocol/nips/blob/master/44.md
 */
public class Nip44 {
    private static final Logger log = LoggerFactory.getLogger(Nip44.class);
    private static final byte VERSION = 2;
    private static final byte[] HKDF_SALT = Sha256Hash.hash("nip44-v2".getBytes(StandardCharsets.UTF_8));
    private static final int MIN_PLAINTEXT_SIZE = 1;
    private static final int MAX_PLAINTEXT_SIZE = 65535;

    /**
     * Encrypt a plaintext message from sender to recipient using NIP-44 v2.
     *
     * @param senderPrivKey sender's secp256k1 private key (32 bytes)
     * @param recipientPubKey recipient's secp256k1 public key (33 bytes compressed)
     * @param plaintext the message to encrypt
     * @return base64-encoded NIP-44 payload
     */
    public static String encrypt(byte[] senderPrivKey, byte[] recipientPubKey, String plaintext) {
        byte[] conversationKey = getConversationKey(senderPrivKey, recipientPubKey);
        byte[] nonce = new byte[32];
        new SecureRandom().nextBytes(nonce);
        return encryptWithConversationKey(conversationKey, nonce, plaintext);
    }

    /**
     * Decrypt a NIP-44 v2 payload.
     *
     * @param recipientPrivKey recipient's secp256k1 private key (32 bytes)
     * @param senderPubKey sender's secp256k1 public key (33 bytes compressed)
     * @param payload base64-encoded NIP-44 payload
     * @return decrypted plaintext
     */
    public static String decrypt(byte[] recipientPrivKey, byte[] senderPubKey, String payload) {
        byte[] conversationKey = getConversationKey(recipientPrivKey, senderPubKey);
        return decryptWithConversationKey(conversationKey, payload);
    }

    /**
     * Compute the conversation key via ECDH + HKDF.
     * conversation_key = HKDF-extract(salt=sha256("nip44-v2"), ikm=ECDH_x)
     */
    static byte[] getConversationKey(byte[] privateKey, byte[] publicKey) {
        // ECDH: multiply recipient's pubkey by sender's privkey
        ECKey pubKey = ECKey.fromPublicOnly(publicKey);
        BigInteger privKeyInt = new BigInteger(1, privateKey);
        // Multiply and normalize the resulting point (BouncyCastle requires
        // affine form for coordinate extraction)
        org.bouncycastle.math.ec.ECPoint sharedPoint = pubKey.getPubKeyPoint().multiply(privKeyInt).normalize();
        // Use only x-coordinate (32 bytes)
        byte[] sharedX = bigIntTo32Bytes(sharedPoint.getAffineXCoord().toBigInteger());

        // HKDF extract+expand: salt=sha256("nip44-v2"), ikm=shared_x, info=empty
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(sharedX, HKDF_SALT, new byte[0]));
        byte[] conversationKey = new byte[32];
        hkdf.generateBytes(conversationKey, 0, 32);
        return conversationKey;
    }

    static String encryptWithConversationKey(byte[] conversationKey, byte[] nonce, String plaintext) {
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        if(plaintextBytes.length < MIN_PLAINTEXT_SIZE || plaintextBytes.length > MAX_PLAINTEXT_SIZE) {
            throw new IllegalArgumentException("Plaintext length out of range");
        }

        // Derive keys from conversation_key + nonce
        byte[] keys = deriveMessageKeys(conversationKey, nonce);
        byte[] chachaKey = Arrays.copyOfRange(keys, 0, 32);
        byte[] chachaNonce = Arrays.copyOfRange(keys, 32, 44);
        byte[] hmacKey = Arrays.copyOfRange(keys, 44, 76);

        // Pad plaintext
        byte[] padded = pad(plaintextBytes);

        // Encrypt with plain ChaCha20 (NOT ChaCha20-Poly1305)
        byte[] ciphertext = chacha20(chachaKey, chachaNonce, padded);

        // HMAC-SHA256(hmac_key, nonce || ciphertext)
        byte[] mac = hmacSha256(hmacKey, Utils.concat(nonce, ciphertext));

        // Assemble payload: version(1) || nonce(32) || ciphertext(variable) || mac(32)
        ByteArrayOutputStream payload = new ByteArrayOutputStream();
        payload.write(VERSION);
        payload.write(nonce, 0, nonce.length);
        payload.write(ciphertext, 0, ciphertext.length);
        payload.write(mac, 0, mac.length);

        return java.util.Base64.getEncoder().encodeToString(payload.toByteArray());
    }

    static String decryptWithConversationKey(byte[] conversationKey, String base64Payload) {
        byte[] payload = java.util.Base64.getDecoder().decode(base64Payload);

        if(payload.length < 97) { // 1 + 32 + 32 (min padded) + 32 (hmac)
            throw new IllegalArgumentException("Payload too short");
        }

        byte version = payload[0];
        if(version != VERSION) {
            throw new IllegalArgumentException("Unsupported NIP-44 version: " + version);
        }

        byte[] nonce = Arrays.copyOfRange(payload, 1, 33);
        byte[] ciphertext = Arrays.copyOfRange(payload, 33, payload.length - 32);
        byte[] mac = Arrays.copyOfRange(payload, payload.length - 32, payload.length);

        // Derive keys
        byte[] keys = deriveMessageKeys(conversationKey, nonce);
        byte[] chachaKey = Arrays.copyOfRange(keys, 0, 32);
        byte[] chachaNonce = Arrays.copyOfRange(keys, 32, 44);
        byte[] hmacKey = Arrays.copyOfRange(keys, 44, 76);

        // Verify HMAC
        byte[] expectedMac = hmacSha256(hmacKey, Utils.concat(nonce, ciphertext));
        if(!constantTimeEquals(mac, expectedMac)) {
            throw new SecurityException("NIP-44 HMAC verification failed");
        }

        // Decrypt with plain ChaCha20
        byte[] padded = chacha20(chachaKey, chachaNonce, ciphertext);

        // Unpad
        return unpad(padded);
    }

    private static byte[] deriveMessageKeys(byte[] conversationKey, byte[] nonce) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(conversationKey, nonce, new byte[0]));
        byte[] keys = new byte[76];
        hkdf.generateBytes(keys, 0, 76);
        return keys;
    }

    /**
     * Plain ChaCha20 stream cipher (no Poly1305 AEAD).
     * NIP-44 uses ChaCha20 for encryption and a separate HMAC-SHA256 for authentication.
     */
    private static byte[] chacha20(byte[] key, byte[] nonce, byte[] data) {
        ChaCha7539Engine chacha = new ChaCha7539Engine();
        chacha.init(true, new ParametersWithIV(new KeyParameter(key), nonce));
        byte[] output = new byte[data.length];
        chacha.processBytes(data, 0, data.length, output, 0);
        return output;
    }

    /**
     * NIP-44 padding: 2-byte big-endian length prefix + data + zero-pad to next power of 2 (min 32).
     */
    static byte[] pad(byte[] plaintext) {
        int unpaddedLen = 2 + plaintext.length;
        int paddedLen = calcPaddedLen(plaintext.length);
        byte[] padded = new byte[paddedLen];
        padded[0] = (byte)((plaintext.length >> 8) & 0xFF);
        padded[1] = (byte)(plaintext.length & 0xFF);
        System.arraycopy(plaintext, 0, padded, 2, plaintext.length);
        // Rest is already zero-filled
        return padded;
    }

    static String unpad(byte[] padded) {
        if(padded.length < 2) {
            throw new IllegalArgumentException("Padded data too short");
        }
        int dataLen = ((padded[0] & 0xFF) << 8) | (padded[1] & 0xFF);
        if(dataLen < MIN_PLAINTEXT_SIZE || dataLen > MAX_PLAINTEXT_SIZE || dataLen + 2 > padded.length) {
            throw new IllegalArgumentException("Invalid padding length: " + dataLen);
        }
        return new String(padded, 2, dataLen, StandardCharsets.UTF_8);
    }

    static int calcPaddedLen(int unpaddedLen) {
        if(unpaddedLen <= 0) return 32;
        int total = unpaddedLen + 2; // 2-byte length prefix
        if(total <= 32) return 32;
        // Next power of 2
        int bits = 32 - Integer.numberOfLeadingZeros(total - 1);
        int chunk = 1 << bits;
        if(chunk < total) chunk <<= 1;
        return chunk;
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) {
        HMac hmac = new HMac(new SHA256Digest());
        hmac.init(new KeyParameter(key));
        hmac.update(data, 0, data.length);
        byte[] result = new byte[32];
        hmac.doFinal(result, 0);
        return result;
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if(a.length != b.length) return false;
        int result = 0;
        for(int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    private static byte[] bigIntTo32Bytes(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if(bytes.length == 32) return bytes;
        if(bytes.length > 32) return Arrays.copyOfRange(bytes, bytes.length - 32, bytes.length);
        byte[] padded = new byte[32];
        System.arraycopy(bytes, 0, padded, 32 - bytes.length, bytes.length);
        return padded;
    }
}
