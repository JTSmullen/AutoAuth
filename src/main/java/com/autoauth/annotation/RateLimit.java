package com.autoauth.annotation;

import java.lang.annotation.*;
import java.util.concurrent.TimeUnit;

/**
 * Enforces rate limiting on a controller class or request-mapping method
 * <p>
 *     Requests get tracked by client identifiers. If a user is authenticated
 *     the rate limiter tracks them by their uuid ({@code user:userId}). For
 *     unauthenticated requests the rate limiter tracks them by their IP address
 *     ({@code ip:clientIp}), resolving the client IP from proxy headers such as
 *     {@code X-Forwareded-For}) when available.
 * </p>
 *
 * <h3>SaaS Tiering @amp; Quotas:</h3>
 * By nesting {@link UserQuota} annotations inside {@link #value()} array
 * you can assign specific request thresholds based on user roles (such as
 * subscription tiers like {@code FREE}, {@code PREMIUM}, or {@code ENTERPRISE}).
 * If an authenticated user has multiple roles defined in the quotas, the rate
 * limited automatically applies the highest limit based on their roles.
 *
 * <h3>Usage Examples:</h3>
 *
 * <h4>1. Basic Rate Limiting</h4>
 * Limits requests to 10 per minute per client (IP or UUID)
 * <pre>{@code
 * @RateLimit(fallbackRequests = 10, window = 1, unit = TimeUnit.MINUTES)
 * @GetMapping("/search")
 * public List<Item> search() {...}
 * }</pre>
 *
 * <h4>2. Tier based SaaS rate limiting</h4>
 * Users with the {@code PREMIUM} role are allowed 100 requests per  30 seconds
 * whereas users with {@code ENTERPRISE} are allowed 1,000. All other users
 * fallback to 5 requests:
 * <pre>{@code
 * @RateLimit(
 *      value = {
 *           @UserQuota(role = "PREMIUM", maxRequests = 100),
 *           @UserQuota(role = "ENTERPRICE", maxRequests = 1000)
 *      },
 *      fallbackRequests = 5,
 *      window = 30,
 *      unit = TimeUnit.SECONDS
 * )
 * @GetMapping("/limited-data")
 * Public Data getPremiumData() {...}
 * }</pre>
 *
 * @see UserQuota
 * @see com.autoauth.aop.RateLimitAspect
 * @since 1.0.0
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RateLimit {

    UserQuota[] value() default{};

    int fallbackRequests() default 5;

    long window() default 1;

    TimeUnit unit() default TimeUnit.MINUTES;

}