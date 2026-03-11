package com.sparrowwallet.drongo.nip05;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;

import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Application-level cache for resolved Nostr contacts.
 * Contacts are keyed by the input identifier (npub or NIP-05 address)
 * and shared across all wallet tabs so resolution only happens once.
 */
public class NostrContactCache {
    public static final long DEFAULT_TTL_SECONDS = 1800L; // 30 minutes
    public static final long REFRESH_TTL_SECONDS = 300L;  // 5 minutes after manual refresh

    private static final Cache<String, List<NostrContact>> contactLists = Caffeine.newBuilder().expireAfter(new Expiry<String, List<NostrContact>>() {
        @Override
        public long expireAfterCreate(String key, List<NostrContact> contacts, long currentTime) {
            return TimeUnit.SECONDS.toNanos(DEFAULT_TTL_SECONDS);
        }

        @Override
        public long expireAfterUpdate(String key, List<NostrContact> contacts, long currentTime, long currentDuration) {
            return TimeUnit.SECONDS.toNanos(DEFAULT_TTL_SECONDS);
        }

        @Override
        public long expireAfterRead(String key, List<NostrContact> contacts, long currentTime, long currentDuration) {
            return currentDuration;
        }
    }).build();

    /** The most recently used input identifier, so other wallet tabs can auto-populate. */
    private static volatile String lastInput;

    private NostrContactCache() {}

    public static List<NostrContact> getContacts(String npubOrNip05) {
        return contactLists.getIfPresent(normalize(npubOrNip05));
    }

    public static void putContacts(String npubOrNip05, List<NostrContact> contacts) {
        String key = normalize(npubOrNip05);
        contactLists.put(key, contacts);
        lastInput = npubOrNip05;
    }

    public static String getLastInput() {
        return lastInput;
    }

    public static void invalidate(String npubOrNip05) {
        contactLists.invalidate(normalize(npubOrNip05));
    }

    private static String normalize(String input) {
        return input == null ? "" : input.trim().toLowerCase();
    }
}
