package com.autoauth.util;

import org.springframework.util.ResourceUtils;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

public class KeyLoader {

    private static final String[] SUPPORTED_ALGORITHMS = {"RSA", "EC", "Ed25519", "EdDSA"};

    private static final Map<String, PrivateKey> privateKeyCache = new ConcurrentHashMap<>();
    private static final Map<String, PublicKey> publicKeyCache = new ConcurrentHashMap<>();

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

    private static String cleanPem(String rawContent) {
        if (rawContent.isBlank()) {
            return "";
        }
        return rawContent.lines()
                .map(String::trim)
                .filter(line -> !line.startsWith("-") && !line.isEmpty())
                .collect(Collectors.joining(""));
    }

    public static PrivateKey loadPrivateKey(String pemKey) {
        String rawContent = resolveKeyContent(pemKey);

        if (privateKeyCache.containsKey(rawContent)) {
            return privateKeyCache.get(rawContent);
        }

        try {
            boolean isPkcs1 = rawContent.contains("-----BEGIN RSA PRIVATE KEY-----");
            String cleanedBase64 = cleanPem(rawContent);
            byte[] encoded = Base64.getDecoder().decode(cleanedBase64);

            if (isPkcs1) {
                encoded = convertPkcs1ToPkcs8(encoded);
            }

            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            PrivateKey privateKey = null;

            for (String alg : SUPPORTED_ALGORITHMS) {
                try {
                    privateKey = KeyFactory.getInstance(alg).generatePrivate(keySpec);
                    break;
                } catch (Exception ignored) {
                }
            }

            if (privateKey == null) {
                throw new IllegalArgumentException("Algorithm not supported or private key format is invalid.");
            }

            privateKeyCache.put(rawContent, privateKey);
            return privateKey;

        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to load Private Key.", e);
        }
    }

    public static PublicKey loadPublicKey(String pemKey) {
        String rawContent = resolveKeyContent(pemKey);

        if (publicKeyCache.containsKey(rawContent)) {
            return publicKeyCache.get(rawContent);
        }

        try {
            boolean isCertificate = rawContent.contains("-----BEGIN CERTIFICATE-----");
            String cleanedBase64 = cleanPem(rawContent);
            byte[] encoded = Base64.getDecoder().decode(cleanedBase64);

            PublicKey publicKey = null;

            if (isCertificate) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                try (ByteArrayInputStream bis = new ByteArrayInputStream(encoded)) {
                    X509Certificate cert = (X509Certificate) cf.generateCertificate(bis);
                    publicKey = cert.getPublicKey();
                }
            } else {
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
                for (String alg : SUPPORTED_ALGORITHMS) {
                    try {
                        publicKey = KeyFactory.getInstance(alg).generatePublic(keySpec);
                        break;
                    } catch (Exception ignored) {
                    }
                }
            }

            if (publicKey == null) {
                throw new IllegalArgumentException("Algorithm not supported or public key format is invalid.");
            }

            publicKeyCache.put(rawContent, publicKey);
            return publicKey;

        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to load Public Key.", e);
        }
    }

    private static byte[] convertPkcs1ToPkcs8(byte[] pkcs1Bytes) {
        int pkcs1Length = pkcs1Bytes.length;
        byte[] rsaOid = {0x30, 0x0d, 0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00};

        int pkcs8Length = pkcs1Length + rsaOid.length + 4;
        byte[] pkcs8Bytes;

        if (pkcs1Length < 128) {
            pkcs8Bytes = new byte[pkcs1Length + 22];
            pkcs8Bytes[0] = 0x30;
            pkcs8Bytes[1] = (byte) (pkcs1Length + 20);
        } else if (pkcs1Length < 256) {
            pkcs8Bytes = new byte[pkcs1Length + 23];
            pkcs8Bytes[0] = 0x30;
            pkcs8Bytes[1] = (byte) 0x81;
            pkcs8Bytes[2] = (byte) (pkcs1Length + 20);
        } else {
            pkcs8Bytes = new byte[pkcs1Length + 24];
            pkcs8Bytes[0] = 0x30;
            pkcs8Bytes[1] = (byte) 0x82;
            pkcs8Bytes[2] = (byte) ((pkcs1Length + 20) >> 8);
            pkcs8Bytes[3] = (byte) (pkcs1Length + 20);
        }

        int offset = pkcs8Bytes[1] == (byte) 0x81 ? 3 : (pkcs8Bytes[1] == (byte) 0x82 ? 4 : 2);
        pkcs8Bytes[offset++] = 0x02;
        pkcs8Bytes[offset++] = 0x01;
        pkcs8Bytes[offset++] = 0x00;

        System.arraycopy(rsaOid, 0, pkcs8Bytes, offset, rsaOid.length);
        offset += rsaOid.length;

        pkcs8Bytes[offset++] = 0x04;
        if (pkcs1Length < 128) {
            pkcs8Bytes[offset++] = (byte) pkcs1Length;
        } else if (pkcs1Length < 256) {
            pkcs8Bytes[offset++] = (byte) 0x81;
            pkcs8Bytes[offset++] = (byte) pkcs1Length;
        } else {
            pkcs8Bytes[offset++] = (byte) 0x82;
            pkcs8Bytes[offset++] = (byte) (pkcs1Length >> 8);
            pkcs8Bytes[offset++] = (byte) pkcs1Length;
        }

        System.arraycopy(pkcs1Bytes, 0, pkcs8Bytes, offset, pkcs1Length);
        return pkcs8Bytes;
    }
}