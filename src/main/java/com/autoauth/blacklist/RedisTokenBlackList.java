package com.autoauth.blacklist;

import org.springframework.data.redis.core.ReactiveRedisTemplate;
import java.time.Duration;

public class RedisTokenBlackList implements TokenBlackList {

    private final ReactiveRedisTemplate<String, String> redisTemplate;

    public RedisTokenBlackList(ReactiveRedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void add(String jti, Duration timeToLive) {

    }

    @Override
    public boolean isBlackListed(String jti) {
        return false;
    }
}
