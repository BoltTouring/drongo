package com.sparrowwallet.drongo.nip05;

import com.sparrowwallet.drongo.Network;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

public class Nip05ResolverTest {

    @BeforeAll
    static void setup() {
        Network.set(Network.MAINNET);
    }

    // --- Unit tests for JSON parsing (no network required) ---

    @Test
    public void extractPubkeyTest() {
        Nip05Resolver resolver = new Nip05Resolver("_@bushbashjapan.fyi");
        String json = "{\"names\":{\"_\":\"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\"}}";
        String pubkey = resolver.extractPubkey(json, "_");
        Assertions.assertEquals("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", pubkey);
    }

    @Test
    public void extractPubkeyWithMultipleNamesTest() {
        Nip05Resolver resolver = new Nip05Resolver("alice@example.com");
        String json = "{\"names\":{\"bob\":\"1111111111111111111111111111111111111111111111111111111111111111\"," +
                "\"alice\":\"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\"," +
                "\"charlie\":\"2222222222222222222222222222222222222222222222222222222222222222\"}}";
        String pubkey = resolver.extractPubkey(json, "alice");
        Assertions.assertEquals("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", pubkey);
    }

    @Test
    public void extractPubkeyNotFoundTest() {
        Nip05Resolver resolver = new Nip05Resolver("missing@example.com");
        String json = "{\"names\":{\"alice\":\"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\"}}";
        String pubkey = resolver.extractPubkey(json, "missing");
        Assertions.assertNull(pubkey);
    }

    @Test
    public void extractPubkeyNoNamesBlockTest() {
        Nip05Resolver resolver = new Nip05Resolver("alice@example.com");
        String json = "{\"other\":{\"key\":\"value\"}}";
        String pubkey = resolver.extractPubkey(json, "alice");
        Assertions.assertNull(pubkey);
    }

    @Test
    public void extractRelaysTest() {
        Nip05Resolver resolver = new Nip05Resolver("_@bushbashjapan.fyi");
        String pubkey = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        String json = "{\"names\":{\"_\":\"" + pubkey + "\"}," +
                "\"relays\":{\"" + pubkey + "\":[\"wss://relay.damus.io\",\"wss://nos.lol\"]}}";
        List<String> relays = resolver.extractRelays(json, pubkey);
        Assertions.assertEquals(2, relays.size());
        Assertions.assertEquals("wss://relay.damus.io", relays.get(0));
        Assertions.assertEquals("wss://nos.lol", relays.get(1));
    }

    @Test
    public void extractRelaysEmptyTest() {
        Nip05Resolver resolver = new Nip05Resolver("_@bushbashjapan.fyi");
        String json = "{\"names\":{\"_\":\"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\"}}";
        List<String> relays = resolver.extractRelays(json, "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
        Assertions.assertTrue(relays.isEmpty());
    }

    @Test
    public void extractSpAddressTest() {
        Nip05Resolver resolver = new Nip05Resolver("_@bushbashjapan.fyi");
        String profileJson = "{\"name\":\"Tanjiro\",\"about\":\"test\",\"sp\":\"sp1qqgrz6j0lcqnc3s5nrfpe75mwt5geuztcfmqgk3e5v5k6rg6eyeaagcthgqcygnrcfxlf0my20700hxaa6pdw5pm2edv00v7rl6yr3rlzq5vqqxkzrc0\"}";
        String sp = resolver.extractSpAddress(profileJson);
        Assertions.assertNotNull(sp);
        Assertions.assertTrue(sp.startsWith("sp1"));
    }

    @Test
    public void extractSpAddressNotPresentTest() {
        Nip05Resolver resolver = new Nip05Resolver("_@bushbashjapan.fyi");
        String profileJson = "{\"name\":\"Someone\",\"about\":\"no SP address here\",\"lud16\":\"user@wallet.com\"}";
        String sp = resolver.extractSpAddress(profileJson);
        Assertions.assertNull(sp);
    }

    @Test
    public void extractEventContentTest() {
        Nip05Resolver resolver = new Nip05Resolver("_@bushbashjapan.fyi");
        // Raw event object (already extracted from EVENT message)
        String eventObject = "{\"id\":\"abc\",\"kind\":0,\"content\":\"{\\\"name\\\":\\\"Test\\\",\\\"sp\\\":\\\"sp1qqtest\\\"}\",\"created_at\":1234}";
        String content = resolver.extractEventContent(eventObject);
        Assertions.assertNotNull(content);
        Assertions.assertTrue(content.contains("\"name\":\"Test\""));
        Assertions.assertTrue(content.contains("\"sp\":\"sp1qqtest\""));
    }

    @Test
    public void extractEventContentWithUnicodeTest() {
        Nip05Resolver resolver = new Nip05Resolver("_@bushbashjapan.fyi");
        String eventObject = "{\"content\":\"{\\\"name\\\":\\\"\\u30c6\\u30b9\\u30c8\\\"}\"}";
        String content = resolver.extractEventContent(eventObject);
        Assertions.assertNotNull(content);
        Assertions.assertTrue(content.contains("テスト")); // Japanese for "test"
    }

    // --- Raw event extraction tests ---

    @Test
    public void extractRawEventObjectTest() {
        Nip05Resolver resolver = new Nip05Resolver("_@bushbashjapan.fyi");
        String eventMessage = "[\"EVENT\",\"sub123\",{\"id\":\"abc123\",\"kind\":0,\"content\":\"{\\\"name\\\":\\\"Test\\\"}\",\"tags\":[]}]";
        String rawEvent = resolver.extractRawEventObject(eventMessage);
        Assertions.assertNotNull(rawEvent);
        Assertions.assertTrue(rawEvent.startsWith("{"));
        Assertions.assertTrue(rawEvent.endsWith("}"));
        Assertions.assertTrue(rawEvent.contains("\"id\":\"abc123\""));
    }

    @Test
    public void extractRawEventObjectWithNestedJsonTest() {
        Nip05Resolver resolver = new Nip05Resolver("_@bushbashjapan.fyi");
        // Content contains nested braces inside the JSON string
        String eventMessage = "[\"EVENT\",\"sub\",{\"id\":\"def\",\"content\":\"{\\\"nested\\\":{\\\"deep\\\":\\\"value\\\"}}\",\"tags\":[]}]";
        String rawEvent = resolver.extractRawEventObject(eventMessage);
        Assertions.assertNotNull(rawEvent);
        Assertions.assertTrue(rawEvent.contains("\"id\":\"def\""));
    }

    // --- Tags and content extraction for serialization ---

    @Test
    public void extractTagsJsonTest() {
        Nip05Resolver resolver = new Nip05Resolver("_@bushbashjapan.fyi");
        String event = "{\"id\":\"abc\",\"tags\":[[\"p\",\"deadbeef\"],[\"e\",\"cafebabe\"]],\"content\":\"test\"}";
        String tags = resolver.extractTagsJson(event);
        Assertions.assertNotNull(tags);
        Assertions.assertEquals("[[\"p\",\"deadbeef\"],[\"e\",\"cafebabe\"]]", tags);
    }

    @Test
    public void extractTagsJsonEmptyTest() {
        Nip05Resolver resolver = new Nip05Resolver("_@bushbashjapan.fyi");
        String event = "{\"id\":\"abc\",\"tags\":[],\"content\":\"test\"}";
        String tags = resolver.extractTagsJson(event);
        Assertions.assertNotNull(tags);
        Assertions.assertEquals("[]", tags);
    }

    @Test
    public void extractContentJsonRawTest() {
        Nip05Resolver resolver = new Nip05Resolver("_@bushbashjapan.fyi");
        String event = "{\"id\":\"abc\",\"content\":\"{\\\"name\\\":\\\"Test\\\"}\",\"tags\":[]}";
        String content = resolver.extractContentJsonRaw(event);
        Assertions.assertNotNull(content);
        Assertions.assertEquals("\"{\\\"name\\\":\\\"Test\\\"}\"", content);
    }

    // --- Signature verification tests ---

    @Test
    public void verifyEventSignaturePubkeyMismatchTest() {
        Nip05Resolver resolver = new Nip05Resolver("_@bushbashjapan.fyi");
        String event = "{\"id\":\"abc\",\"pubkey\":\"1111111111111111111111111111111111111111111111111111111111111111\"," +
                "\"sig\":\"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"," +  // padding to 128
                "\"kind\":0,\"created_at\":1234,\"tags\":[],\"content\":\"{}\"}";
        // Expected pubkey is different from event pubkey
        boolean result = resolver.verifyEventSignature(event, "2222222222222222222222222222222222222222222222222222222222222222");
        Assertions.assertFalse(result, "Should fail when pubkey doesn't match expected");
    }

    @Test
    public void verifyEventSignatureMissingFieldsTest() {
        Nip05Resolver resolver = new Nip05Resolver("_@bushbashjapan.fyi");
        // Missing sig field
        String event = "{\"id\":\"abc\",\"pubkey\":\"1111111111111111111111111111111111111111111111111111111111111111\"," +
                "\"kind\":0,\"created_at\":1234,\"tags\":[],\"content\":\"{}\"}";
        boolean result = resolver.verifyEventSignature(event, "1111111111111111111111111111111111111111111111111111111111111111");
        Assertions.assertFalse(result, "Should fail when required fields are missing");
    }

    @Test
    public void invalidHrnTest() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> new Nip05Resolver("noplaces"));
        Assertions.assertThrows(IllegalArgumentException.class, () -> new Nip05Resolver("too@many@places"));
    }

    // --- Cache tests ---

    @Test
    public void cacheTest() {
        Nip05Payment payment = new Nip05Payment("test@example.com", null, "deadbeef");
        Nip05PaymentCache.putNip05Payment("test@example.com", payment);
        Nip05Payment cached = Nip05PaymentCache.getNip05Payment("test@example.com");
        Assertions.assertNotNull(cached);
        Assertions.assertEquals("test@example.com", cached.hrn());
        Assertions.assertEquals("deadbeef", cached.nostrPubkey());
    }

    @Test
    public void cacheMissTest() {
        Nip05Payment cached = Nip05PaymentCache.getNip05Payment("nonexistent@example.com");
        Assertions.assertNull(cached);
    }

    // --- Live integration test (requires network + libsecp256k1) ---

    @Test
    public void liveResolveTest() throws Nip05Exception {
        // This test requires network access — resolves _@bushbashjapan.fyi
        // and verifies it returns a valid Silent Payment address.
        // With signature verification enabled, this also proves the event
        // was cryptographically signed by the expected Nostr keypair.
        Nip05Resolver resolver = new Nip05Resolver("_@bushbashjapan.fyi");
        Optional<Nip05Payment> result = resolver.resolve();
        if(result.isPresent()) {
            Assertions.assertNotNull(result.get().spAddress(), "SP address should not be null");
            Assertions.assertTrue(result.get().spAddress().getAddress().startsWith("sp1"), "SP address should start with sp1");
            Assertions.assertNotNull(result.get().nostrPubkey(), "Pubkey should not be null");
            Assertions.assertEquals(64, result.get().nostrPubkey().length(), "Pubkey should be 64 hex chars");
            System.out.println("Resolved _@bushbashjapan.fyi (with signature verification):");
            System.out.println("  Pubkey: " + result.get().nostrPubkey());
            System.out.println("  SP Address: " + result.get().spAddress().getAddress());
        } else {
            Assertions.fail("Could not resolve _@bushbashjapan.fyi — check that the NIP-05 identity exists and has an sp field in the kind 0 profile");
        }
    }
}
