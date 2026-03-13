package com.sparrowwallet.drongo.nip05;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class Nip44Test {
    @Test
    public void testConversationKey() {
        byte[] sec1 = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000001");
        byte[] sec2 = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000002");
        ECKey key2 = ECKey.fromPrivate(sec2);
        byte[] pub2 = key2.getPubKey(true);

        byte[] convKey = Nip44.getConversationKey(sec1, pub2);
        assertEquals("c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d", Utils.bytesToHex(convKey));
    }

    @Test
    public void testFullPayload() {
        byte[] sec1 = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000001");
        byte[] sec2 = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000002");
        ECKey key2 = ECKey.fromPrivate(sec2);
        byte[] pub2 = key2.getPubKey(true);

        byte[] convKey = Nip44.getConversationKey(sec1, pub2);
        byte[] nonce = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000001");
        String payload = Nip44.encryptWithConversationKey(convKey, nonce, "a");
        assertEquals("AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb", payload);
    }

    @Test
    public void testRoundTrip() {
        byte[] sec1 = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000001");
        byte[] sec2 = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000002");
        ECKey key2 = ECKey.fromPrivate(sec2);
        byte[] pub2 = key2.getPubKey(true);
        ECKey key1 = ECKey.fromPrivate(sec1);
        byte[] pub1 = key1.getPubKey(true);

        String encrypted = Nip44.encrypt(sec1, pub2, "hello from sparrow");
        String decrypted = Nip44.decrypt(sec2, pub1, encrypted);
        assertEquals("hello from sparrow", decrypted);
    }
}
