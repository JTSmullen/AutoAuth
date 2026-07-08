package com.autoauth.jwt;

import com.autoauth.config.AutoAuthProperties;
import com.autoauth.model.AutoAuthUser;
import com.autoauth.model.TokenPair;
import io.jsonwebtoken.Jwts;

import io.jsonwebtoken.security.SecureDigestAlgorithm;

import java.security.PrivateKey;
import java.util.Date;
import java.util.UUID;

public class JwtGenerator {
    private final JwtKeyProvider keyProvider;
    private final AutoAuthProperties properties;

    public JwtGenerator (JwtKeyProvider keyProvider, AutoAuthProperties properties) {
        this.keyProvider = keyProvider;
        this.properties = properties;
    }

    public String generateAccessToken(AutoAuthUser user){
        long expirationTimeMillis = System.currentTimeMillis() + (properties.getExpirationMinutes() * 60 * 1000);

        var builder = Jwts.builder()
                .header().keyId(keyProvider.getKid()).and()
                .issuer(properties.getIssuer())
                .audience().add(properties.getAudience()).and()
                .id(UUID.randomUUID().toString())
                .subject(user.userId())
                .claim("type", "access")
                .claim("roles", user.roles())
                .issuedAt(new Date())
                .expiration(new Date(expirationTimeMillis));

        if (user.customClaims() != null) {
            user.customClaims().forEach(builder::claim);
        }

        return builder
                .signWith(keyProvider.getPrivateKey(),
                        determineSigningAlgorithm(keyProvider.getPrivateKey()))
                .compact();
    }

    public String generateRefreshToken(AutoAuthUser user) {

        long expirationTimeMillis = System.currentTimeMillis() + (properties.getRefreshExpirationMinutes() * 60 * 1000);

        return Jwts.builder()
                .header().keyId(keyProvider.getKid()).and()
                .issuer(properties.getIssuer())
                .audience().add(properties.getAudience()).and()
                .id(UUID.randomUUID().toString())
                .subject(user.userId())
                .claim("type", "refresh")
                .issuedAt(new Date())
                .expiration(new Date(expirationTimeMillis))
                .signWith(keyProvider.getPrivateKey(),
                        determineSigningAlgorithm(keyProvider.getPrivateKey()))
                .compact();
    }

    private SecureDigestAlgorithm determineSigningAlgorithm(PrivateKey key) {
        String algo = key.getAlgorithm();
        if ("RSA".equals(algo)) {
            return Jwts.SIG.RS256;
        } else if ("EC".equals(algo)) {
            return Jwts.SIG.ES256;
        } else if ("Ed25519".equals(algo) || "EdDSA".equals(algo)) {
            return Jwts.SIG.EdDSA;
        }
        throw new IllegalArgumentException("Unsupported signing key algorithm: " + algo);
    }

    public TokenPair generateTokenPair(AutoAuthUser user) {
        return new TokenPair(generateAccessToken(user), generateRefreshToken(user));
    }
}
