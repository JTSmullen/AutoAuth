package com.autoauth.util;

import org.springframework.util.ResourceUtils;

import java.io.File;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.stream.Collectors;

public class KeyLoader {

    private static final String[] SUPPORTED_ALGORITHMS = {"RSA", "EC", "Ed25519", "EdDSA"};

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

            for (String alg : SUPPORTED_ALGORITHMS) {
                try {
                    return KeyFactory.getInstance(alg).generatePrivate(keySpec);
                } catch (Exception ignored) {
                }
            }
            throw new IllegalArgumentException("Algorithm not supported or key format is invalid.");
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to load Private Key. Ensure it is a valid PKCS8 PEM format.", e);
        }
    }

    public static PublicKey loadPublicKey(String pemKey) {
        try {
            String cleanedBase64 = cleanPem(pemKey);
            byte[] encoded = Base64.getDecoder().decode(cleanedBase64);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);

            for (String alg : SUPPORTED_ALGORITHMS) {
                try {
                    return KeyFactory.getInstance(alg).generatePublic(keySpec);
                } catch (Exception ignored) {
                }
            }
            throw new IllegalArgumentException("Algorithm not supported or key format is invalid.");
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to load Public Key. Ensure it is a valid X509 PEM format.", e);
        }
    }
}