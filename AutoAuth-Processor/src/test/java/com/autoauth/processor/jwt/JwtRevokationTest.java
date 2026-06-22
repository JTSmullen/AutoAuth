package com.autoauth.processor.jwt;

import com.autoauth.processor.blacklist.TokenBlackList;
import com.autoauth.processor.config.AutoAuthProperties;
import com.autoauth.processor.model.AutoAuthUser;
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

        // ADDED: Using RSA Keys instead of symmetric string
        properties.setPrivateKey(TestRsaKeys.PRIVATE_KEY_PEM);
        properties.setPublicKey(TestRsaKeys.PUBLIC_KEY_PEM);
        properties.setExpirationMinutes(60);

        keyProvider = new JwtKeyProvider(properties);

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
    void shouldSuccessfullyRevokeTokenAndPreventValidation() {
        AutoAuthUser user = new AutoAuthUser("user123", List.of("user"), null);
        String token = generator.generateToken(user);

        validator.revokeToken(token);

        assertThrows(SecurityException.class, () -> validator.validateAndExtractUser(token));
    }

    @Test
    void shouldGracefullyHandleRevokingAnAlreadyExpiredToken() throws InterruptedException {
        properties.setExpirationMinutes(0);
        generator = new JwtGenerator(keyProvider, properties);

        AutoAuthUser user = new AutoAuthUser("user123", List.of("user"), null);
        String token = generator.generateToken(user);

        Thread.sleep(10);

        assertDoesNotThrow(() -> validator.revokeToken(token));
    }

    @Test
    void shouldThrowExceptionWhenRevokingTamperedToken() {
        AutoAuthUser user = new AutoAuthUser("user123", List.of("user"), null);
        String token = generator.generateToken(user);
        String tamperedToken = token.substring(0, token.length() - 4) + "aaaa";

        assertThrows(IllegalArgumentException.class, () -> validator.revokeToken(tamperedToken));
    }

    @Test
    void shouldAllowValidTokensThatAreNotRevoked() {
        AutoAuthUser user = new AutoAuthUser("user123", List.of("user"), null);
        String token1 = generator.generateToken(user);
        String token2 = generator.generateToken(user);

        validator.revokeToken(token1);

        assertThrows(SecurityException.class, () -> validator.validateAndExtractUser(token1));
        assertDoesNotThrow(() -> validator.validateAndExtractUser(token2));
    }
}