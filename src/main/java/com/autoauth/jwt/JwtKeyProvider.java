package com.autoauth.jwt;

import com.autoauth.config.AutoAuthProperties;
import com.autoauth.util.KeyLoader;

import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class JwtKeyProvider {

    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final String kid;
    private final Map<String, PublicKey> verificationKeys = new ConcurrentHashMap<>();

    public JwtKeyProvider(AutoAuthProperties properties) {
        PrivateKey loadedPriv = null;
        PublicKey loadedPub = null;

        if (properties.getPrivateKey() != null && !properties.getPrivateKey().isBlank()) {
            loadedPriv = KeyLoader.loadPrivateKey(properties.getPrivateKey());
        }

        if (properties.getPublicKey() != null && !properties.getPublicKey().isBlank()) {
            loadedPub = KeyLoader.loadPublicKey(properties.getPublicKey());
        }

        // Auto-derive RSA public key if only CRT private key was supplied
        if (loadedPub == null && loadedPriv instanceof RSAPrivateCrtKey rsaPriv) {
            try {
                RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(
                        rsaPriv.getModulus(),
                        rsaPriv.getPublicExponent()
                );
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                loadedPub = keyFactory.generatePublic(publicKeySpec);
            } catch (Exception e) {
                throw new IllegalStateException("Failed to derive RSA public key from private key", e);
            }
        }

        this.privateKey = loadedPriv;
        this.publicKey = loadedPub;

        if (this.publicKey != null) {
            this.kid = generateDeterministicKid(this.publicKey);
            // register current active key
            this.verificationKeys.put(this.kid, this.publicKey);
        } else {
            this.kid = "autoauth-default-key";
        }
    }

    // sign private key
    public PrivateKey getPrivateKey() {
        if (privateKey == null) {
            throw new IllegalStateException("Private key is not configured. Cannot sign tokens.");
        }
        return privateKey;
    }

    // current primary public key for signing (supports rotation)
    public PublicKey getPublicKey() {
        if (publicKey == null) {
            throw new IllegalStateException("Public key is not configured. Cannot validate tokens.");
        }
        return publicKey;
    }

    // looks up verification by kid
    public PublicKey getPublicKey(String kid) {
        if (kid == null || kid.isBlank() || kid.equals(this.kid)) {
            return this.publicKey;
        }
        return verificationKeys.get(kid);
    }

    public String getKid() {
        return kid;
    }

    // helper function for rotation allowing past public keys to be used during
    // rotation period
    public void registerVerificationKey(String kid, PublicKey key) {
        if (kid != null && key != null) {
            this.verificationKeys.put(kid, key);
        }
    }

    public Map<String, PublicKey> getAllVerificationKeys() {
        return Collections.unmodifiableMap(verificationKeys);
    }

    private String generateDeterministicKid(PublicKey pubKey) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(pubKey.getEncoded());
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not found. Cannot generate kid.", e);
        }
    }
}