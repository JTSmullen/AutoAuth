package com.autoauth.annotation;

import com.autoauth.config.AutoAuthAutoConfiguration;
import org.springframework.context.annotation.Import;
import java.lang.annotation.*;

/**
 * Enables automatic config of autoauth security
 * <p>
 *     Use this annotation on a Spring Config class (usually the main
 *     {@code @SpringBootApplication} class) auto imports filters,
 *     security chains, aspects, and services to secure the app
 * </p>
 *
 * <h2>Bootstrapped Features:</h2>
 * <ul>
 *     <li><b>Stateless Security Filter Chain:</b> Auto secure all endpoints
 *     except those marked with {@link PublicEndpoint} or those
 *     whitelisted in application.properties. </li>
 *     <li><b>JWT Verification &amp; Generation:</b>
 *     Configures {@code JwtGenerator} and {@code JwtValidator}
 *     for access and refresh token lifecycles (RS256).</li>
 *     <li><b>JWKS Endpoint:</b> Auto exposes an RFC-compliant Json web key
 *     at {@code /.well-known/jwks.json} for public key retrieval.</li>
 * </ul>
 *
 * <h2>Usage Example:</h2>
 * <pre>{@code
 * @SpringBootApplication
 * @EnableAutoAuth
 * public class Application {
 *     public static void main(String[] args) {
 *         SpringApplication.run(Application.class, args);
 *     }
 * }}</pre>
 *
 * @see AutoAuthAutoConfiguration
 * @since 1.0.0
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(AutoAuthAutoConfiguration.class)
public @interface EnableAutoAuth {}