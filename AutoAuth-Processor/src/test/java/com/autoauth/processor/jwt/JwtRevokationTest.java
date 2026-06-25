package com.autoauth.processor.jwt;

import com.autoauth.processor.blacklist.TokenBlackList;
import com.autoauth.processor.config.AutoAuthProperties;
import com.autoauth.processor.model.AutoAuthUser;
import com.autoauth.processor.model.TokenPair;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

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
    void setUp() {
        properties = new AutoAuthProperties();

        // Using RSA Keys
        properties.setPrivateKey(TestRsaKeys.PRIVATE_KEY_PEM);
        properties.setPublicKey(TestRsaKeys.PUBLIC_KEY_PEM);
        properties.setExpirationMinutes(60);
        properties.setRefreshExpirationMinutes(10080); // Ensure refresh expiration is set

        keyProvider = new JwtKeyProvider(properties);

        // Dummy in-memory blacklist for testing
        dummyBlackList = new TokenBlackList() {
            private final Set<String> revokedJtis = new HashSet<>();
            @Override
            public void add(String jti, Duration ttl) { revokedJtis.add(jti); }
            @Override
            public boolean isBlackListed(String jti) { return revokedJtis.contains(jti); }
        };

        generator = new JwtGenerator(keyProvider, properties);
        validator = new JwtValidator(keyProvider, dummyBlackList);
    }

    @Test
    void shouldSuccessfullyRevokeAccessTokenAndPreventValidation() {
        // Given
        AutoAuthUser user = new AutoAuthUser("user123", List.of("user"), null);
        String accessToken = generator.generateAccessToken(user);

        // When
        validator.revokeToken(accessToken);

        // Then: Validation should fail with SecurityException because it's blacklisted
        assertThrows(SecurityException.class, () -> validator.validateAndExtractUser(accessToken));
    }

    @Test
    void shouldSuccessfullyRevokeRefreshTokenWithoutAffectingAccessToken() {
        // Given: A full token pair
        AutoAuthUser user = new AutoAuthUser("user123", List.of("user"), null);
        TokenPair tokenPair = generator.generateTokenPair(user);

        // When: We revoke ONLY the refresh token
        validator.revokeToken(tokenPair.refreshToken());

        // Then: Validating the refresh token (with the "refresh" type) should fail
        assertThrows(SecurityException.class, () ->
                validator.validateAndExtractUser(tokenPair.refreshToken(), "refresh")
        );

        // However, the access token should still be perfectly valid!
        assertDoesNotThrow(() -> validator.validateAndExtractUser(tokenPair.accessToken()));
    }

    @Test
    void shouldGracefullyHandleRevokingAnAlreadyExpiredToken() throws InterruptedException {
        // Given: Tokens expire immediately
        properties.setExpirationMinutes(0);
        generator = new JwtGenerator(keyProvider, properties);

        AutoAuthUser user = new AutoAuthUser("user123", List.of("user"), null);
        String token = generator.generateAccessToken(user);

        // Wait a fraction of a second to ensure it is fully expired
        Thread.sleep(10);

        // When/Then: Revoking it should NOT throw an exception, it should gracefully ignore it
        assertDoesNotThrow(() -> validator.revokeToken(token));
    }

    @Test
    void shouldThrowExceptionWhenRevokingTamperedToken() {
        // Given
        AutoAuthUser user = new AutoAuthUser("user123", List.of("user"), null);
        String token = generator.generateAccessToken(user);

        // Tamper with the cryptographic signature
        String tamperedToken = token.substring(0, token.length() - 4) + "aaaa";

        // When/Then: Revoking a fake token should throw an IllegalArgumentException
        assertThrows(IllegalArgumentException.class, () -> validator.revokeToken(tamperedToken));
    }

    @Test
    void shouldAllowValidTokensThatAreNotRevoked() {
        // Given
        AutoAuthUser user = new AutoAuthUser("user123", List.of("user"), null);

        // Generate two completely distinct access tokens for the same user
        String token1 = generator.generateAccessToken(user);
        String token2 = generator.generateAccessToken(user);

        // When
        validator.revokeToken(token1);

        // Then: Token 1 fails, Token 2 succeeds
        assertThrows(SecurityException.class, () -> validator.validateAndExtractUser(token1));
        assertDoesNotThrow(() -> validator.validateAndExtractUser(token2));
    }
}