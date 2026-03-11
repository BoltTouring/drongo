package com.sparrowwallet.drongo.nip05;

import com.sparrowwallet.drongo.silentpayments.SilentPaymentAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Persists Nostr contacts to a JSON file in the Sparrow data directory.
 * Stores the input identifier (npub/NIP-05) and the resolved contact list.
 * Contacts are loaded on startup and refreshed from relays when the user requests.
 */
public class NostrContactStore {
    private static final Logger log = LoggerFactory.getLogger(NostrContactStore.class);
    private static final String FILENAME = "nostr-contacts.json";

    // Simple JSON patterns — avoids adding a JSON library dependency to Drongo
    private static final Pattern INPUT_PATTERN = Pattern.compile("\"input\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern PUBKEY_PATTERN = Pattern.compile("\"pubkey\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern NAME_PATTERN = Pattern.compile("\"displayName\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern SP_PATTERN = Pattern.compile("\"spAddress\"\\s*:\\s*\"(sp1[a-zA-HJ-NP-Z0-9]+)\"");
    private static final Pattern NIP05_PATTERN = Pattern.compile("\"nip05\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern VERIFIED_PATTERN = Pattern.compile("\"signatureVerified\"\\s*:\\s*(true|false)");

    private NostrContactStore() {}

    /**
     * Save contacts and the input identifier to a JSON file.
     *
     * @param dataDir the Sparrow data directory (from Storage.getSparrowDir())
     * @param input the npub or NIP-05 that was resolved
     * @param contacts the resolved contact list
     */
    public static void save(File dataDir, String input, List<NostrContact> contacts) {
        File file = new File(dataDir, FILENAME);
        try(Writer writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8))) {
            writer.write("{\n");
            writer.write("  \"input\": \"" + escapeJson(input) + "\",\n");
            writer.write("  \"savedAt\": " + System.currentTimeMillis() + ",\n");
            writer.write("  \"contacts\": [\n");
            for(int i = 0; i < contacts.size(); i++) {
                NostrContact c = contacts.get(i);
                writer.write("    {\n");
                writer.write("      \"pubkey\": \"" + escapeJson(c.pubkey()) + "\",\n");
                writer.write("      \"displayName\": \"" + escapeJson(c.displayName()) + "\",\n");
                if(c.hasSilentPaymentAddress()) {
                    writer.write("      \"spAddress\": \"" + escapeJson(c.spAddress().getAddress()) + "\",\n");
                }
                if(c.nip05() != null) {
                    writer.write("      \"nip05\": \"" + escapeJson(c.nip05()) + "\",\n");
                }
                writer.write("      \"signatureVerified\": " + c.signatureVerified() + "\n");
                writer.write("    }" + (i < contacts.size() - 1 ? "," : "") + "\n");
            }
            writer.write("  ]\n");
            writer.write("}\n");
            log.info("Saved " + contacts.size() + " Nostr contacts to " + file.getAbsolutePath());
        } catch(IOException e) {
            log.error("Failed to save Nostr contacts", e);
        }
    }

    /**
     * Load saved contacts from the JSON file.
     *
     * @param dataDir the Sparrow data directory
     * @return optional containing the input identifier and contact list, or empty if no file exists
     */
    public static Optional<SavedContacts> load(File dataDir) {
        File file = new File(dataDir, FILENAME);
        if(!file.exists()) {
            return Optional.empty();
        }

        try {
            String json = new String(java.nio.file.Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);

            Matcher inputMatcher = INPUT_PATTERN.matcher(json);
            String input = inputMatcher.find() ? inputMatcher.group(1) : null;
            if(input == null) {
                return Optional.empty();
            }

            List<NostrContact> contacts = new ArrayList<>();

            // Split by contact objects
            int searchFrom = 0;
            while(true) {
                int objStart = json.indexOf('{', json.indexOf("\"contacts\"") > 0 ? Math.max(searchFrom, json.indexOf("\"contacts\"")) : searchFrom);
                if(objStart < 0 || objStart <= searchFrom) break;

                int objEnd = json.indexOf('}', objStart);
                if(objEnd < 0) break;

                String block = json.substring(objStart, objEnd + 1);
                searchFrom = objEnd + 1;

                // Skip the outer object
                Matcher pkMatcher = PUBKEY_PATTERN.matcher(block);
                if(!pkMatcher.find()) continue;

                String pubkey = pkMatcher.group(1);
                String name = extractField(block, NAME_PATTERN);
                String spStr = extractField(block, SP_PATTERN);
                String nip05 = extractField(block, NIP05_PATTERN);
                Matcher verMatcher = VERIFIED_PATTERN.matcher(block);
                boolean verified = verMatcher.find() && "true".equals(verMatcher.group(1));

                SilentPaymentAddress spAddress = null;
                if(spStr != null) {
                    try {
                        spAddress = SilentPaymentAddress.from(spStr);
                    } catch(Exception e) {
                        log.debug("Invalid SP address in saved contact: " + spStr);
                    }
                }

                String displayName = name != null ? name : pubkey.substring(0, 8) + "...";
                contacts.add(new NostrContact(pubkey, displayName, spAddress, nip05, null, verified));
            }

            log.info("Loaded " + contacts.size() + " Nostr contacts from " + file.getAbsolutePath());
            return Optional.of(new SavedContacts(input, contacts));
        } catch(Exception e) {
            log.error("Failed to load Nostr contacts", e);
            return Optional.empty();
        }
    }

    private static String extractField(String block, Pattern pattern) {
        Matcher m = pattern.matcher(block);
        return m.find() ? m.group(1) : null;
    }

    private static String escapeJson(String s) {
        if(s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    /**
     * Container for a saved contacts list with the original input identifier.
     */
    public record SavedContacts(String input, List<NostrContact> contacts) {}
}
