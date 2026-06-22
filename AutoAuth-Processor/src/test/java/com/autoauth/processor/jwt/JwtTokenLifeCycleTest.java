package com.autoauth.processor.jwt;

import com.autoauth.processor.blacklist.TokenBlackList;
import com.autoauth.processor.config.AutoAuthProperties;
import com.autoauth.processor.model.AutoAuthUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class JwtTokenLifeCycleTest {

    private JwtKeyProvider keyProvider;
    private AutoAuthProperties properties;
    private JwtGenerator generator;
    private JwtValidator validator;
    private TokenBlackList blackList;

    // REMOVED THE CONSTRUCTOR

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        properties = new AutoAuthProperties();
        properties.setJwtSecret("test-secret-must-be-hashed-by-provider");
        properties.setExpirationMinutes(60);

        keyProvider = new JwtKeyProvider(properties);

        // ADDED: Create a simple dummy implementation for the interface
        blackList = new TokenBlackList() {
            @Override
            public void add(String jti, Duration ttl) {
                // Do nothing for lifecycle tests
            }

            @Override
            public boolean isBlackListed(String jti) {
                return false; // Tokens are never blacklisted in this test class
            }
        };

        generator = new JwtGenerator(keyProvider, properties);
        validator = new JwtValidator(keyProvider, blackList);
    }

    @Test
    void shouldGenerateAndValidateTokenSuccessfully() {
        AutoAuthUser originalUser = new AutoAuthUser("user123", List.of("admin", "user"), null);

        String token = generator.generateToken(originalUser);
        assertNotNull(token);
        assertFalse(token.isBlank());

        AutoAuthUser extractedUser = validator.validateAndExtractUser(token);

        assertEquals(originalUser.userId(), extractedUser.userId());
        assertEquals(originalUser.roles().size(), extractedUser.roles().size());
        assertTrue(extractedUser.roles().contains("admin"));
        assertTrue(extractedUser.roles().contains("user"));
    }

    @Test
    void shouldThrowExceptionWhenTokenIsTamperedWith() {
        AutoAuthUser user = new AutoAuthUser("user123", List.of("user"), null);
        String token = generator.generateToken(user);

        // Tamper with the token's signature
        String tamperedToken = token.substring(0, token.length() - 4) + "aaaa";

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
                validator.validateAndExtractUser(tamperedToken)
        );

        assertTrue(exception.getMessage().contains("Invalid or expired JWT"));
    }

    @Test
    void shouldThrowExceptionWhenTokenIsExpired() throws InterruptedException {
        // Set expiration to 0 minutes so it expires immediately
        properties.setExpirationMinutes(0);

        // Re-initialize generator with the new 0-minute property
        generator = new JwtGenerator(keyProvider, properties);

        AutoAuthUser user = new AutoAuthUser("user123", List.of("user"), null);
        String token = generator.generateToken(user);

        // Optional but recommended: Add a tiny delay to guarantee the token's timestamp is in the past
        Thread.sleep(10);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
                validator.validateAndExtractUser(token)
        );

        assertTrue(exception.getMessage().contains("Invalid or expired JWT"));
    }
}