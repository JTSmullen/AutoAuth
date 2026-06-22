package com.autoauth.processor.blacklist;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import java.time.Duration;

public class CafeTokenBlackList implements TokenBlackList {

    private final Cache<String, Long> cache = Caffeine.newBuilder()
            .expireAfter(new Expiry<String, Long>() {
                @Override
                public long expireAfterCreate(String key, Long durationNanos, long currentTime) {
                    return durationNanos;
                }
                @Override
                public long expireAfterUpdate(String key, Long durationNanos, long currentTime, long currentDuration) {
                    return currentDuration;
                }
                @Override
                public long expireAfterRead(String key, Long durationNanos, long currentTime, long currentDuration) {
                    return currentDuration;
                }
            })
            .build();

    @Override
    public void add(String jti, Duration timeToLive) {
        cache.put(jti, timeToLive.toNanos());
    }

    @Override
    public boolean isBlackListed(String jti) {
        return cache.getIfPresent(jti) != null;
    }
}