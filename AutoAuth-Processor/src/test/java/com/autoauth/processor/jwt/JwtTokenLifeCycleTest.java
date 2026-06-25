package com.autoauth.processor.jwt;

import com.autoauth.processor.blacklist.TokenBlackList;
import com.autoauth.processor.config.AutoAuthProperties;
import com.autoauth.processor.model.AutoAuthUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JwtTokenLifeCycleTest {

    private JwtKeyProvider keyProvider;
    private AutoAuthProperties properties;
    private JwtGenerator generator;
    private JwtValidator validator;
    private TokenBlackList blackList;

    @BeforeEach
    void setUp() {
        properties = new AutoAuthProperties();

        // Using our new RSA keys instead of the old JWT Secret string
        properties.setPrivateKey(TestRsaKeys.PRIVATE_KEY_PEM);
        properties.setPublicKey(TestRsaKeys.PUBLIC_KEY_PEM);
        properties.setExpirationMinutes(60);
        properties.setRefreshExpirationMinutes(10080); // 7 days for refresh tokens

        keyProvider = new JwtKeyProvider(properties);

        blackList = new TokenBlackList() {
            @Override
            public void add(String jti, Duration ttl) {}
            @Override
            public boolean isBlackListed(String jti) { return false; }
        };

        generator = new JwtGenerator(keyProvider, properties);
        validator = new JwtValidator(keyProvider, blackList);
    }

    @Test
    void shouldGenerateAndValidateAccessTokenSuccessfully() {
        // Given (using the clean 2-parameter constructor)
        AutoAuthUser originalUser = new AutoAuthUser("user123", List.of("admin", "user"), null);

        // When
        String token = generator.generateAccessToken(originalUser);

        // Then
        assertNotNull(token);
        assertFalse(token.isBlank());

        AutoAuthUser extractedUser = validator.validateAndExtractUser(token);
        assertEquals(originalUser.userId(), extractedUser.userId());
        assertTrue(extractedUser.roles().contains("admin"));
        assertTrue(extractedUser.roles().contains("user"));
    }

    @Test
    void shouldGenerateAndExtractCustomClaims() {
        // Given: A user with extra embedded data
        Map<String, Object> claims = Map.of(
                "email", "developer@test.com",
                "tenantId", "company_abc_99"
        );
        AutoAuthUser originalUser = new AutoAuthUser("user456", List.of("user"), claims);

        // When
        String token = generator.generateAccessToken(originalUser);
        AutoAuthUser extractedUser = validator.validateAndExtractUser(token);

        // Then: Verify custom claims are fully preserved
        assertEquals("developer@test.com", extractedUser.customClaims().get("email"));
        assertEquals("company_abc_99", extractedUser.customClaims().get("tenantId"));

        // Ensure standard claims didn't leak into the custom claims map
        assertNull(extractedUser.customClaims().get("sub"));
        assertNull(extractedUser.customClaims().get("type"));
    }

    @Test
    void shouldGenerateAndValidateRefreshTokenSuccessfully() {
        // Given
        AutoAuthUser originalUser = new AutoAuthUser("user123", List.of("user"), null);

        // When
        String refreshToken = generator.generateRefreshToken(originalUser);

        // Then: We must explicitly tell the validator to expect a "refresh" type
        AutoAuthUser extractedUser = validator.validateAndExtractUser(refreshToken, "refresh");
        assertEquals(originalUser.userId(), extractedUser.userId());
    }

    @Test
    void shouldThrowSecurityExceptionWhenUsingRefreshTokenAsAccessToken() {
        // Given
        AutoAuthUser user = new AutoAuthUser("user123", List.of("user"), null);
        String refreshToken = generator.generateRefreshToken(user);

        // When/Then: Validating it using the default method (which expects "access") MUST FAIL
        SecurityException exception = assertThrows(SecurityException.class, () ->
                validator.validateAndExtractUser(refreshToken)
        );

        assertTrue(exception.getMessage().contains("Invalid token type"));
    }

    @Test
    void shouldThrowExceptionWhenTokenIsTamperedWith() {
        AutoAuthUser user = new AutoAuthUser("user123", List.of("user"), null);
        String token = generator.generateAccessToken(user);

        // Tamper with the token's cryptographic signature
        String tamperedToken = token.substring(0, token.length() - 4) + "aaaa";

        assertThrows(IllegalArgumentException.class, () -> validator.validateAndExtractUser(tamperedToken));
    }

    @Test
    void shouldThrowExceptionWhenTokenIsExpired() throws InterruptedException {
        // Given: Expiration is 0 minutes
        properties.setExpirationMinutes(0);
        generator = new JwtGenerator(keyProvider, properties);

        AutoAuthUser user = new AutoAuthUser("user123", List.of("user"), null);
        String token = generator.generateAccessToken(user);

        // Ensure expiration triggers
        Thread.sleep(10);

        // When/Then
        assertThrows(IllegalArgumentException.class, () -> validator.validateAndExtractUser(token));
    }
}