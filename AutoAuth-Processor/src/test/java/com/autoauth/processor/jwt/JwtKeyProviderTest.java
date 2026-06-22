package com.autoauth.processor.jwt;

import com.autoauth.processor.config.AutoAuthProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JwtKeyProviderTest {

    private AutoAuthProperties properties;

    @BeforeEach
    void setUp() {
        properties = new AutoAuthProperties();
    }

    @Test
    void shouldThrowExceptionWhenRetrievingMissingPrivateKey() {
        properties.setPrivateKey(null);
        JwtKeyProvider keyProvider = new JwtKeyProvider(properties);

        assertThrows(IllegalStateException.class, keyProvider::getPrivateKey);
    }

    @Test
    void shouldThrowExceptionWhenRetrievingMissingPublicKey() {
        properties.setPublicKey("   ");
        JwtKeyProvider keyProvider = new JwtKeyProvider(properties);

        assertThrows(IllegalStateException.class, keyProvider::getPublicKey);
    }

    @Test
    void shouldSuccessfullyLoadPrivateKey() {
        properties.setPrivateKey(TestRsaKeys.PRIVATE_KEY_PEM);
        JwtKeyProvider keyProvider = new JwtKeyProvider(properties);

        assertNotNull(keyProvider.getPrivateKey());
        assertEquals("RSA", keyProvider.getPrivateKey().getAlgorithm());
    }

    @Test
    void shouldSuccessfullyLoadPublicKey() {
        properties.setPublicKey(TestRsaKeys.PUBLIC_KEY_PEM);
        JwtKeyProvider keyProvider = new JwtKeyProvider(properties);

        assertNotNull(keyProvider.getPublicKey());
        assertEquals("RSA", keyProvider.getPublicKey().getAlgorithm());
    }

    @Test
    void shouldThrowExceptionOnMalformedPemString() {
        properties.setPublicKey("-----BEGIN PUBLIC KEY-----\nNotABase64String!\n-----END PUBLIC KEY-----");

        assertThrows(IllegalArgumentException.class, () -> new JwtKeyProvider(properties));
    }
}