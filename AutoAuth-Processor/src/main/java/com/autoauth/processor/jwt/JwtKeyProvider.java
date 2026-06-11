package com.autoauth.processor.jwt;

import com.autoauth.processor.config.AutoAuthProperties;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class JwtKeyProvider {

  private final SecretKey secretKey;

  private JwtKeyProvider(AutoAuthProperties properties) {
    String secret = properties.getJwtSecret();

    if (secret == null || secret.isBlank()) {
      throw new IllegalStateException("AutoAuth: 'autoauth.jwt-secret' is missing from the application properties! You must set a secret to generate JWTs.");
    }

    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] keyBytes = digest.digest(secret.getBytes(StandardCharsets.UTF_8));

      this.secretKey = Keys.hmacShaKeyFor(keyBytes);

    catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("Failed to initialize JWT Key Provider", e);
    }
  }

  public SecretKey getKey() {
    return this.secretKey;
  }
}
