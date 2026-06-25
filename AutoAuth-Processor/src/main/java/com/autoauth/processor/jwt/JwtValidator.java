package com.autoauth.processor.jwt;

import com.autoauth.processor.blacklist.TokenBlackList;
import com.autoauth.processor.exception.TokenRevokedException;
import com.autoauth.processor.model.AutoAuthUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

public class JwtValidator {
  private final JwtKeyProvider keyProvider;
  private final TokenBlackList blackList;

  public JwtValidator(JwtKeyProvider keyProvider, TokenBlackList blackList) {
    this.keyProvider = keyProvider;
    this.blackList = blackList;
  }

  public AutoAuthUser validateAndExtractUser(String token) {
    return validateAndExtractUser(token, "access");
  }

  public AutoAuthUser validateAndExtractUser(String token, String expectedType) {
    try {
      Claims claims = Jwts.parser()
              .verifyWith(keyProvider.getPublicKey())
              .build()
              .parseSignedClaims(token)
              .getPayload();

      String tokenType = claims.get("type", String.class);
      if (!expectedType.equals(tokenType)) {
        throw new SecurityException("Invalid token type. Expected: : " + expectedType);
      }

      String jti = claims.getId();
      if (jti != null && blackList.isBlackListed(jti)) {
        throw new TokenRevokedException("Token has been revoked");
      }

      String userId = claims.getSubject();

      @SuppressWarnings("unchecked")
      List<String> roles = claims.get("roles", List.class);

      java.util.Map<String, Object> customClaims = new java.util.HashMap<>(claims);

      customClaims.remove(Claims.SUBJECT);
      customClaims.remove(Claims.EXPIRATION);
      customClaims.remove(Claims.ISSUED_AT);
      customClaims.remove(Claims.ID);
      customClaims.remove("roles");
      customClaims.remove("type");

      return new AutoAuthUser(userId, roles != null ? roles : List.of(), customClaims);

    } catch (TokenRevokedException e) {
      throw new SecurityException("Invalid or expired JWT: " + e.getMessage());
    } catch (JwtException e) {
      throw new IllegalArgumentException("Invalid or expired JWT: " + e.getMessage());
    }
  }

  public void revokeToken(String token) {
    try {
      Claims claims = Jwts.parser()
              .verifyWith(keyProvider.getPublicKey())
              .build()
              .parseSignedClaims(token)
              .getPayload();

      String jti = claims.getId();
      if (jti == null) {
        throw new IllegalArgumentException("Token does not contain a JWT ID (jti) and cannot be revoked");
      }

      Date expiration = claims.getExpiration();

      if (expiration != null) {
        Instant expiresAt = expiration.toInstant();
        Instant now = Instant.now();

        if (expiresAt.isAfter(now)) {
          Duration ttl = Duration.between(now, expiresAt);
          blackList.add(jti, ttl);
        }
      }
    } catch (ExpiredJwtException ignored) {
    } catch (JwtException e) {
      throw new IllegalArgumentException("Invalid JWT provided for revocation: " + e.getMessage());
    }
  }
}