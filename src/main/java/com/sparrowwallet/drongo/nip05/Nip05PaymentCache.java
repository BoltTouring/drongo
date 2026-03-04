package com.sparrowwallet.drongo.nip05;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;

import java.util.concurrent.TimeUnit;

public class Nip05PaymentCache {
    public static final long MAX_TTL_SECONDS = 86400L;  // 24 hours
    public static final long MIN_TTL_SECONDS = 1800L;   // 30 minutes
    public static final long DEFAULT_TTL_SECONDS = 3600L; // 1 hour

    private static final Cache<String, Nip05Payment> nip05Payments = Caffeine.newBuilder().expireAfter(new Expiry<String, Nip05Payment>() {
        @Override
        public long expireAfterCreate(String hrn, Nip05Payment payment, long currentTime) {
            return TimeUnit.SECONDS.toNanos(DEFAULT_TTL_SECONDS);
        }

        @Override
        public long expireAfterUpdate(String hrn, Nip05Payment payment, long currentTime, long currentDuration) {
            return expireAfterCreate(hrn, payment, currentTime);
        }

        @Override
        public long expireAfterRead(String hrn, Nip05Payment payment, long currentTime, long currentDuration) {
            return currentDuration;
        }
    }).build();

    private Nip05PaymentCache() {}

    public static Nip05Payment getNip05Payment(String hrn) {
        return nip05Payments.getIfPresent(hrn);
    }

    public static void putNip05Payment(String hrn, Nip05Payment payment) {
        nip05Payments.put(hrn, payment);
    }
}
