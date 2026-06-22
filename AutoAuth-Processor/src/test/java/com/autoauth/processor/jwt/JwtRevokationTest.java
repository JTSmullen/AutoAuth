package com.autoauth.processor.jwt;

import com.autoauth.processor.blacklist.TokenBlackList;
import com.autoauth.processor.config.AutoAuthProperties;
import com.autoauth.processor.model.AutoAuthUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class JwtTokenRevocationTest {

    private JwtKeyProvider keyProvider;
    private AutoAuthProperties properties;
    private JwtGenerator generator;
    private JwtValidator validator;
    private TokenBlackList dummyBlackList;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        properties = new AutoAuthProperties();
        properties.setJwtSecret("test-secret-must-be-hashed-by-provider-for-revocation");
        properties.setExpirationMinutes(60);

        keyProvider = new JwtKeyProvider(properties);

        // 1. Create a fast, in-memory fake BlackList just for testing
        dummyBlackList = new TokenBlackList() {
            private final Set<String> revokedJtis = new HashSet<>();

            @Override
            public void add(String jti, Duration ttl) {
                revokedJtis.add(jti);
            }

            @Override
            public boolean isBlackListed(String jti) {
                return revokedJtis.contains(jti);
            }
        };

        generator = new JwtGenerator(keyProvider, properties);
        validator = new JwtValidator(keyProvider, dummyBlackList);
    }

    @Test
    void shouldSuccessfullyRevokeTokenAndPreventValidation() {
        // Arrange: Generate a valid token
        AutoAuthUser user = new AutoAuthUser("user123", List.of("user"), null);
        String token = generator.generateToken(user);

        // Act: Revoke the token
        validator.revokeToken(token);

        // Assert: Attempting to validate it now should throw a SecurityException
        SecurityException exception = assertThrows(SecurityException.class, () ->
                validator.validateAndExtractUser(token)
        );

        assertEquals("Token has been revoked", exception.getMessage());
    }

    @Test
    void shouldGracefullyHandleRevokingAnAlreadyExpiredToken() throws InterruptedException {
        // Arrange: Create a token that expires immediately
        properties.setExpirationMinutes(0);
        generator = new JwtGenerator(keyProvider, properties);

        AutoAuthUser user = new AutoAuthUser("user123", List.of("user"), null);
        String token = generator.generateToken(user);

        // Wait a tiny bit to ensure the token is fully in the past
        Thread.sleep(10);

        // Act & Assert: Revoking an expired token should NOT throw an exception.
        // It should silently catch ExpiredJwtException and succeed.
        assertDoesNotThrow(() -> validator.revokeToken(token));
    }

    @Test
    void shouldThrowExceptionWhenRevokingTamperedToken() {
        // Arrange: Generate and tamper with a token
        AutoAuthUser user = new AutoAuthUser("user123", List.of("user"), null);
        String token = generator.generateToken(user);
        String tamperedToken = token.substring(0, token.length() - 4) + "aaaa";

        // Act & Assert: It should throw an IllegalArgumentException
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
                validator.revokeToken(tamperedToken)
        );

        assertTrue(exception.getMessage().contains("Invalid JWT provided for revocation"));
    }

    @Test
    void shouldAllowValidTokensThatAreNotRevoked() {
        // Arrange: Generate two different tokens
        AutoAuthUser user = new AutoAuthUser("user123", List.of("user"), null);
        String token1 = generator.generateToken(user);
        String token2 = generator.generateToken(user);

        // Act: Revoke ONLY token 1
        validator.revokeToken(token1);

        // Assert: Token 1 is dead, but Token 2 is still valid (because of unique jti UUIDs!)
        assertThrows(SecurityException.class, () -> validator.validateAndExtractUser(token1));
        assertDoesNotThrow(() -> validator.validateAndExtractUser(token2));
    }
}