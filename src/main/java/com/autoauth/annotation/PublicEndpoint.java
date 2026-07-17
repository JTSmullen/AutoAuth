package com.autoauth.annotation;

import java.lang.annotation.*;

/**
 * marks a controller class or mapping method as publicly accessible
 * <p>
 *     Endpoints marked with {@code @PublicEndpoint} bypass automatic jwt validation
 *     filter and do not require auth or auth cookie
 * </p>
 *
 * <h3>Usage Scopes:</h3>
 * <ul>
 *     <li><b>Method Level:</b> Apply {@code @PublicEndpoint}
 *     to a mapping method such as {@code @GetMapping} whitelists
 *     only that specific endpoint path.</li>
 *     <li><b>Class Level:</b> Apply {@code @PublicEndpoint} to a
 *     controller class such as {@code @RestController} whitelists
 *     all request paths mapped within aforementioned controller class</li>
 * </ul>
 *
 * <h3>Usage Examples:</h3>
 *
 * <h4>1. Method-level whitelisting</h4>
 * <pre>{@code
 * @RestController
 * @RequestMapping("/api/users")
 * public class UserController {
 *      // Secure (requires valid JWT)
 *      @GetMapping("profile")
 *      public Profile getProfile() {...}
 *
 *      // Public (no JWT reequired)
 *      @PublicEndpoint
 *      @PostMapping("/register")
 *      public void register() {...}
 * }}</pre>
 *
 * <h4>2. Class-level whitelisting</h4>
 * <pre>{@code
 * @PublicEndpoint
 * @RestController
 * @RequestMapping("/api/public")
 * public class PublicController {
 *      // Public (no JWT required)
 *      @GetMapping("/status")
 *      public status getStatus() {...}
 * }}</pre>
 *
 * @since 1.0.0
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface PublicEndpoint {}