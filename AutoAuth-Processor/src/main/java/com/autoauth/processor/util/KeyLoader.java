package com.autoauth.processor.util;

import java.io.File;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.stream.Collectors;
import org.springframework.util.ResourceUtils;

public class KeyLoader {

    private static String resolveKeyContent(String input) {
        if (input == null || input.isBlank()) {
            return "";
        }

        String trimmedInput = input.trim();

        if (trimmedInput.contains("\n") || trimmedInput.contains("\r")) {
            return input;
        }

        if (trimmedInput.startsWith("classpath:") || trimmedInput.startsWith("file:")) {
            try {
                File file = ResourceUtils.getFile(trimmedInput);
                return Files.readString(file.toPath());
            } catch (Exception e) {
                throw new IllegalArgumentException("Failed to read key file from location: " + trimmedInput, e);
            }
        }

        try {
            File file = new File(trimmedInput);
            if (file.exists() && file.isFile()) {
                return Files.readString(file.toPath());
            }
        } catch (Exception ignored) {
        }

        return input;
    }

    private static String cleanPem(String pemKey) {
        String rawContent = resolveKeyContent(pemKey);
        if (rawContent.isBlank()) {
            return "";
        }
        return rawContent.lines()
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