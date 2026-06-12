package com.autoauth.processor.jwt;

import com.autoauth.processor.config.AutoAuthProperties;
import com.autoauth.processor.model.AutoAuthUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class JwtTokenLifeCycleTest {

    private JwtKeyProvider keyProvider;
    private AutoAuthProperties properties;
    private JwtGenerator generator;
    private JwtValidator validator;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        properties = new AutoAuthProperties();
        properties.setJwtSecret("test-secret-must-be-hashed-by-provider");
        properties.setExpirationMinutes(60);

        keyProvider = new JwtKeyProvider(properties);
        generator = new JwtGenerator(keyProvider, properties);
        validator = new JwtValidator(keyProvider);
    }

    @Test
    void shouldGenerateAndValidateTokenSuccessfully() {
        AutoAuthUser originalUser = new AutoAuthUser("user123", List.of("admin", "user"));

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
        AutoAuthUser user = new AutoAuthUser("user123", List.of("user"));
        String token = generator.generateToken(user);

        String tamperedToken = token.substring(0, token.length() - 4) + "aaaa";

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
                validator.validateAndExtractUser(tamperedToken)
        );

        assertTrue(exception.getMessage().contains("Invalid or expired JWT"));
    }

    @Test
    void shouldThrowExceptionWhenTokenIsExpired() {
        properties.setExpirationMinutes(0);

        generator = new JwtGenerator(keyProvider, properties);

        AutoAuthUser user = new AutoAuthUser("user123", List.of("user"));
        String token = generator.generateToken(user);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
                validator.validateAndExtractUser(token)
        );

        assertTrue(exception.getMessage().contains("Invalid or expired JWT"));
    }
}