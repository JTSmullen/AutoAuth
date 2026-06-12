package com.autoauth.processor.jwt;

import com.autoauth.processor.model.AutoAuthUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

import java.util.List;

public class JwtValidator {
  private final JwtKeyProvider keyProvider;

  public JwtValidator(JwtKeyProvider keyProvider) {
    this.keyProvider = keyProvider;
  }

  public AutoAuthUser validateAndExtractUser(String token) {
    try {
      Claims claims = Jwts.parser()
        .verifyWith(keyProvider.getKey())
        .build()
        .parseSignedClaims(token)
        .getPayload();

      String userId = claims.getSubject();

      @SuppressWarnings("unchecked")
      List<String> roles = claims.get("roles", List.class);

      return new AutoAuthUser(userId, roles != null ? roles : List.of());
    } catch (JwtException e) {
      throw new IllegalArgumentException("Invalid or expired JWT: " + e.getMessage());
    }
  }
}
