package com.autoauth.blacklist;

import org.springframework.data.redis.core.StringRedisTemplate;
import java.time.Duration;

public class RedisTokenBlackList implements TokenBlackList {

    private final StringRedisTemplate redisTemplate;

    public RedisTokenBlackList(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void add(String jti, Duration timeToLive) {
        redisTemplate.opsForValue().set("blacklist:" + jti, "revoked", timeToLive);
    }

    @Override
    public boolean isBlackListed(String jti) {
        return redisTemplate.hasKey("blacklist:" + jti);
    }

    public void banUser(String userId, Duration duration) {
        redisTemplate.opsForValue().set("banned:" + userId, "true", duration);
    }

    public void unbanUser(String userId) {
        redisTemplate.delete("banned:" + userId);
    }

    public boolean isUserBanned(String userId) {
        return redisTemplate.hasKey("banned:" + userId);
    }
}