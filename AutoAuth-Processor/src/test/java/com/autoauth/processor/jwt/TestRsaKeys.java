package com.autoauth.processor.jwt;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

public class TestRsaKeys {
    public static final String PRIVATE_KEY_PEM;
    public static final String PUBLIC_KEY_PEM;

    static {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair pair = keyGen.generateKeyPair();

            PRIVATE_KEY_PEM = "-----BEGIN PRIVATE KEY-----\n" +
                    Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()) +
                    "\n-----END PRIVATE KEY-----";

            PUBLIC_KEY_PEM = "-----BEGIN PUBLIC KEY-----\n" +
                    Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()) +
                    "\n-----END PUBLIC KEY-----";
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate RSA test keys", e);
        }
    }
}