package com.autoauth.processor.util;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.stream.Collectors;

public class KeyLoader {

    private static String cleanPem(String pemKey) {
        if (pemKey == null) {
            return "";
        }
        return pemKey.lines()
                .map(String::trim)
                .filter(line -> !line.startsWith("-") && !line.isEmpty())
                .collect(Collectors.joining(""));
    }

    public static PrivateKey loadPrivateKey(String pemKey) {
        try {
            String cleanedBase64 = cleanPem(pemKey);
            byte[] encoded = Base64.getDecoder().decode(cleanedBase64);

            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to load RSA Private Key. Ensure it is a valid PKCS8 PEM format.", e);
        }
    }

    public static PublicKey loadPublicKey(String pemKey) {
        try {
            String cleanedBase64 = cleanPem(pemKey);
            byte[] encoded = Base64.getDecoder().decode(cleanedBase64);

            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
            return KeyFactory.getInstance("RSA").generatePublic(keySpec);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to load RSA Public Key. Ensure it is a valid X509 PEM format.", e);
        }
    }
}
