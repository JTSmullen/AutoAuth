package com.autoauth.processor.jwt;

import com.autoauth.processor.blacklist.TokenBlackList;
import com.autoauth.processor.config.AutoAuthProperties;
import com.autoauth.processor.model.AutoAuthUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

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

        // ADDED: Using our new RSA keys instead of the old JWT Secret string
        properties.setPrivateKey(TestRsaKeys.PRIVATE_KEY_PEM);
        properties.setPublicKey(TestRsaKeys.PUBLIC_KEY_PEM);
        properties.setExpirationMinutes(60);

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
    void shouldGenerateAndValidateTokenSuccessfully() {
        AutoAuthUser originalUser = new AutoAuthUser("user123", List.of("admin", "user"), null);
        String token = generator.generateToken(originalUser);

        assertNotNull(token);
        assertFalse(token.isBlank());

        AutoAuthUser extractedUser = validator.validateAndExtractUser(token);
        assertEquals(originalUser.userId(), extractedUser.userId());
        assertTrue(extractedUser.roles().contains("admin"));
    }

    @Test
    void shouldThrowExceptionWhenTokenIsTamperedWith() {
        AutoAuthUser user = new AutoAuthUser("user123", List.of("user"), null);
        String token = generator.generateToken(user);

        String tamperedToken = token.substring(0, token.length() - 4) + "aaaa";

        assertThrows(IllegalArgumentException.class, () -> validator.validateAndExtractUser(tamperedToken));
    }

    @Test
    void shouldThrowExceptionWhenTokenIsExpired() throws InterruptedException {
        properties.setExpirationMinutes(0);
        generator = new JwtGenerator(keyProvider, properties);

        AutoAuthUser user = new AutoAuthUser("user123", List.of("user"), null);
        String token = generator.generateToken(user);

        Thread.sleep(10); // Ensure expiration triggers

        assertThrows(IllegalArgumentException.class, () -> validator.validateAndExtractUser(token));
    }
}