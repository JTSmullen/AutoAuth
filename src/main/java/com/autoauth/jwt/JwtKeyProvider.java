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

public class JwtKeyProvider {

    private PrivateKey privateKey;
    private PublicKey publicKey;
    private String kid;

    public JwtKeyProvider(AutoAuthProperties properties) {
        if (properties.getPrivateKey() != null && !properties.getPrivateKey().isBlank()) {
            this.privateKey = KeyLoader.loadPrivateKey(properties.getPrivateKey());
        }

        if (properties.getPublicKey() != null && !properties.getPublicKey().isBlank()) {
            this.publicKey = KeyLoader.loadPublicKey(properties.getPublicKey());
        }

        if (this.publicKey == null && this.privateKey instanceof RSAPrivateCrtKey) {
            try {
                RSAPrivateCrtKey rsaPrivateCrtKey = (RSAPrivateCrtKey) this.privateKey;
                RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(
                        rsaPrivateCrtKey.getModulus(),
                        rsaPrivateCrtKey.getPublicExponent()
                );
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                this.publicKey = keyFactory.generatePublic(publicKeySpec);
            } catch (Exception e) {}
        }

        if (this.publicKey != null) {
            this.kid = generateDeterministicKid(this.publicKey);
        } else {
            this.kid = "autoauth-default-key";
        }
    }

    public PrivateKey getPrivateKey() {
        if (privateKey == null) {
            throw new IllegalStateException("RSA Private key is not configured | cannot generate tokens");
        }
        return privateKey;
    }

    public PublicKey getPublicKey() {
        if (publicKey == null) {
            throw new IllegalStateException("RSA public key is not configured. Cannot validate tokens");
        }
        return publicKey;
    }

    public String getKid() {
        return kid;
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