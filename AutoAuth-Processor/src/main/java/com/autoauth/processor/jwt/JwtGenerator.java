package com.autoauth.processor.jwt;

import com.autoauth.processor.config.AutoAuthProperties;
import com.autoauth.processor.model.AutoAuthUser;
import io.jsonwebtoken.Jwts;

import java.util.Date;

public class JwtGenerator {
  private final JwtKeyProvider keyProvider;
  private final AutoAuthProperties properties;

  public JwtGenerator (JwtKeyProvider keyProvider, AutoAuthProperties properties) {
    this.keyProvider = keyProvider;
    this.properties = properties;
  }

  public String generateToken (AutoAuthUser user) {
    long expirationTimeMillis = System.currentTimeMillis() + (properties.getExpirationMinutes() * 60 * 1000);

    return Jwts.builder()
      .subject(user.userId())
      .claim("roles", user.roles())
      .issuedAt(new Date())
      .expiration(new Date(expirationTimeMillis))
      .signWith(keyProvider.getKey(), Jwts.SIG.HS256)
      .compact();
  }
}
