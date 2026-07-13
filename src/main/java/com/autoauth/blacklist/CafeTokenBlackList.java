package com.autoauth.blacklist;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.time.Duration;

public class CafeTokenBlackList implements TokenBlackList {

    private final Cache<String, Boolean> blacklistCache = Caffeine.newBuilder().build();
    private final Cache<String, Boolean> banCache = Caffeine.newBuilder().build();

    @Override
    public void add(String jti, Duration timeToLive) {
        blacklistCache.put(jti, true);
    }

    @Override
    public boolean isBlackListed(String jti) {
        return blacklistCache.getIfPresent(jti) != null;
    }

    public void banUser(String userId, Duration duration) {
        banCache.put(userId, true);
    }

    public boolean isUserBanned(String userId) {
        return banCache.getIfPresent(userId) != null;
    }
}