package com.autoauth.processor.jwt;

import com.autoauth.processor.config.AutoAuthProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

class JwtKeyProviderTest {

    private AutoAuthProperties properties;

    @BeforeEach
    void setUp() {

        properties = new AutoAuthProperties();

    }

    @Test
    void shouldThrowExceptionWhenSecretIsMissing() {

        properties.setJwtSecret(null);

        IllegalStateException exception = assertThrows(IllegalStateException.class, () -> new JwtKeyProvider(properties));

        assertTrue(exception.getMessage().contains("autoauth.jwt-secret"));

    }

    @Test
    void shouldThrowExceptionWhenSecretIsBlack() {

        properties.setJwtSecret("   ");

        assertThrows(IllegalStateException.class, () -> new JwtKeyProvider(properties));

    }

    @Test
    void shouldGenerateKeyWhenSecretIsValid() throws NoSuchAlgorithmException {

        properties.setJwtSecret("my-temporary-secret-key-for-testing");

        JwtKeyProvider keyProvider = new JwtKeyProvider(properties);
        SecretKey key = keyProvider.getKey();

        assertNotNull(key);
        assertEquals("HmacSHA256", key.getAlgorithm());

    }

}