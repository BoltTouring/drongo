package com.sparrowwallet.drongo.nip05;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.Argon2KeyDeriver;
import com.sparrowwallet.drongo.crypto.Key;
import com.sparrowwallet.drongo.protocol.Bech32;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

/**
 * Encrypts and persists a Nostr nsec to disk using Argon2id key derivation + AES-256-GCM.
 * The user enters a password once; subsequent sessions decrypt automatically with the same password.
 *
 * File format (nostr-key.enc):
 *   Line 1: base64(salt) — 16-byte Argon2 salt
 *   Line 2: base64(iv || ciphertext || tag) — 12-byte IV + AES-GCM encrypted nsec + 16-byte auth tag
 */
public class NostrKeyStore {
    private static final Logger log = LoggerFactory.getLogger(NostrKeyStore.class);
    private static final String FILENAME = "nostr-key.enc";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_BITS = 128;

    private NostrKeyStore() {}

    /**
     * Encrypt and save an nsec, protected by the given password.
     *
     * @param dataDir Sparrow data directory
     * @param nsec the bech32 nsec to store
     * @param password the encryption password
     */
    public static void save(File dataDir, String nsec, CharSequence password) throws Exception {
        // Validate nsec
        byte[] privKey = decodeNsec(nsec);
        if(privKey.length != 32) {
            throw new IllegalArgumentException("Invalid nsec");
        }

        // Derive AES key from password via Argon2
        Argon2KeyDeriver deriver = new Argon2KeyDeriver();
        Key key = deriver.deriveKey(password);
        byte[] salt = deriver.getSalt();

        // Encrypt nsec with AES-256-GCM
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[GCM_IV_LENGTH];
        random.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getKeyBytes(), "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] ciphertext = cipher.doFinal(nsec.getBytes(StandardCharsets.UTF_8));

        // Write to file
        byte[] payload = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, payload, 0, iv.length);
        System.arraycopy(ciphertext, 0, payload, iv.length, ciphertext.length);

        File file = new File(dataDir, FILENAME);
        try(BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
            writer.write(Base64.getEncoder().encodeToString(salt));
            writer.newLine();
            writer.write(Base64.getEncoder().encodeToString(payload));
            writer.newLine();
        }

        log.info("Nostr key saved to " + file.getAbsolutePath());

        // Clear sensitive data
        Arrays.fill(privKey, (byte)0);
        Arrays.fill(key.getKeyBytes(), (byte)0);
    }

    /**
     * Load and decrypt the stored nsec.
     *
     * @param dataDir Sparrow data directory
     * @param password the decryption password
     * @return the decrypted nsec string, or empty if no file exists
     */
    public static Optional<String> load(File dataDir, CharSequence password) throws Exception {
        File file = new File(dataDir, FILENAME);
        if(!file.exists()) {
            return Optional.empty();
        }

        String saltB64;
        String payloadB64;
        try(BufferedReader reader = new BufferedReader(new FileReader(file))) {
            saltB64 = reader.readLine();
            payloadB64 = reader.readLine();
        }

        if(saltB64 == null || payloadB64 == null) {
            return Optional.empty();
        }

        byte[] salt = Base64.getDecoder().decode(saltB64);
        byte[] payload = Base64.getDecoder().decode(payloadB64);

        if(payload.length < GCM_IV_LENGTH + 16) {
            throw new IllegalStateException("Encrypted key file is corrupted");
        }

        // Derive same AES key from password + stored salt
        Argon2KeyDeriver deriver = new Argon2KeyDeriver(salt);
        Key key = deriver.deriveKey(password);

        // Decrypt
        byte[] iv = Arrays.copyOfRange(payload, 0, GCM_IV_LENGTH);
        byte[] ciphertext = Arrays.copyOfRange(payload, GCM_IV_LENGTH, payload.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.getKeyBytes(), "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] plaintext = cipher.doFinal(ciphertext);

        Arrays.fill(key.getKeyBytes(), (byte)0);

        return Optional.of(new String(plaintext, StandardCharsets.UTF_8));
    }

    /**
     * Check if an encrypted nsec file exists.
     */
    public static boolean exists(File dataDir) {
        return new File(dataDir, FILENAME).exists();
    }

    /**
     * Delete the stored nsec file.
     */
    public static boolean delete(File dataDir) {
        File file = new File(dataDir, FILENAME);
        return file.exists() && file.delete();
    }

    /**
     * Decode an nsec bech32 string to a 32-byte private key.
     */
    public static byte[] decodeNsec(String nsec) {
        Bech32.Bech32Data decoded = Bech32.decode(nsec, 90);
        if(!decoded.hrp.equals("nsec")) {
            throw new IllegalArgumentException("Expected nsec prefix, got: " + decoded.hrp);
        }
        return Bech32.convertBits(decoded.data, 0, decoded.data.length, 5, 8, false);
    }
}
