package com.autoauth.processor.jwt;

import com.autoauth.processor.config.AutoAuthProperties;
import com.autoauth.processor.util.KeyLoader;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class JwtKeyProvider {

  private PrivateKey privateKey;
  private PublicKey publicKey;

  public JwtKeyProvider(AutoAuthProperties properties) {
    if (properties.getPrivateKey() != null && !properties.getPrivateKey().isBlank()) {
      this.privateKey = KeyLoader.loadPrivateKey(properties.getPrivateKey());
    }

    if (properties.getPublicKey() != null && !properties.getPublicKey().isBlank()) {
      this.publicKey = KeyLoader.loadPublicKey(properties.getPublicKey());
    }
  }

  public PrivateKey getPrivateKey() {
    if(privateKey == null) {
      throw new IllegalStateException("RSA Private key is not configured | cannot generate tokens");
    }
    return privateKey;
  }

  public PublicKey getPublicKey() {
    if(publicKey == null) {
      throw new IllegalStateException("RSA public key is not configured. Cannot validate tokens");
    }
    return publicKey;
  }
}
