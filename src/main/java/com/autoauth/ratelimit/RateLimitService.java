package com.autoauth.ratelimit;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class RateLimitService {

    private final Map<String, long[]> cache = new ConcurrentHashMap<>();

    public boolean isAllowed(String key, int maxRequests, long windowMillis) {
        long now = System.currentTimeMillis();

        return cache.compute(key, (k, data) -> {
            if (data == null || now > data[1]) {
                return new long[]{1, now + windowMillis};
            }

            data[0]++;
            return data;
        })[0] <= maxRequests;
    }
}