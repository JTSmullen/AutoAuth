package com.autoauth.blacklist;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import org.checkerframework.checker.index.qual.NonNegative;

import java.time.Duration;

public class CafeTokenBlackList implements TokenBlackList {

    // container to hold variable ttl for each entry
    private record CacheEntry(Duration ttl) {}

    // revoked jti cache
    private final Cache<String, CacheEntry> tokenBlackList;

    // banned jti | user id cache
    private final Cache<String, CacheEntry> bannedUsers;

    public CafeTokenBlackList() {
        this.tokenBlackList = buildVariableExpiryCache();
        this.bannedUsers = buildVariableExpiryCache();
    }

    private Cache<String, CacheEntry> buildVariableExpiryCache() {
        return Caffeine.newBuilder()
                .expireAfter(new Expiry<String, CacheEntry>() {
                    @Override
                    public long expireAfterCreate(String key, CacheEntry entry, long currentTime){
                        return entry.ttl().toNanos();
                    }

                    @Override
                    public long expireAfterUpdate(String key, CacheEntry entry, long currentTime, @NonNegative long currentDuration) {
                        return entry.ttl().toNanos();
                    }

                    @Override
                    public long expireAfterRead(String key, CacheEntry entry, long currentTime, @NonNegative long currentDuration) {
                        return currentDuration;
                    }
                })
                .build();
    }

    // Add jti to blacklist cache with jwt current ttl
    @Override
    public void add(String jti, Duration ttl) {
        if (jti != null && !jti.isBlank() && ttl != null && !ttl.isNegative() && !ttl.isZero()) {
            tokenBlackList.put(jti, new CacheEntry(ttl));
        }
    }

    @Override
    public boolean isBlackListed(String jti) {
        if (jti == null || jti.isBlank()) {
            return false;
        }
        return tokenBlackList.getIfPresent(jti) != null;
    }

    @Override
    public void banUser(String userId, Duration duration) {
        if (userId != null && !userId.isBlank() && duration != null
                &&  !duration.isNegative() && !duration.isZero()) {

            bannedUsers.put(userId, new CacheEntry(duration));

        }
    }

    @Override
    public boolean isUserBanned(String userId) {
        if (userId == null || userId.isBlank()) {
            return false;
        }
        return bannedUsers.getIfPresent(userId) != null;
    }

    @Override
    public void unbanUser(String userId) {
        if (userId != null && !userId.isBlank()){
            bannedUsers.invalidate(userId);
        }
    }
}