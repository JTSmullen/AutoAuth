package com.autoauth.processor.blacklist;

import org.springframework.data.redis.core.StringRedisTemplate;
import java.time.Duration;

public class RedisTokenBlackList implements TokenBlackList{

    private final StringRedisTemplate redisTemplate;
    private static final String PREFIX = "jwt:blacklist:";

    public RedisTokenBlackList(StringRedisTemplate redisTemplate){
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void add(String jti, Duration ttl) {
        redisTemplate.opsForValue().set(PREFIX + jti, "revoked", ttl);
    }

    @Override
    public boolean isBlackListed(String jti) {
        return redisTemplate.hasKey(PREFIX + jti);
    }

}
