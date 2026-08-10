package com.autoauth.jwt;

import com.autoauth.blacklist.TokenBlackList;
import com.autoauth.config.AutoAuthProperties;
import com.autoauth.exception.TokenRevokedException;
import com.autoauth.model.AutoAuthUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

public class JwtValidator {
    private final JwtKeyProvider keyProvider;
    private final TokenBlackList blackList;
    private final JwtParser jwtParser;

    public JwtValidator(JwtKeyProvider keyProvider, TokenBlackList blackList, AutoAuthProperties properties) {
        this.keyProvider = keyProvider;
        this.blackList = blackList;

        JwtParserBuilder parserBuilder = Jwts.parser()
                .verifyWith(keyProvider.getPublicKey());

        if (properties.getIssuer() != null && !properties.getIssuer().isBlank()) {
            parserBuilder.requireIssuer(properties.getIssuer());
        }

        if (properties.getAudience() != null && !properties.getAudience().isBlank()) {
            parserBuilder.requireAudience(properties.getAudience());
        }

        this.jwtParser = parserBuilder.build();
    }

    public AutoAuthUser validateAndExtractUser(String token) {
        return validateAndExtractUser(token, "access");
    }

    public AutoAuthUser validateAndExtractUser(String token, String expectedType) {
        try {
            Claims claims = jwtParser
                    .parseSignedClaims(token)
                    .getPayload();

            String tokenType = claims.get("type", String.class);
            if (!expectedType.equals(tokenType)) {
                throw new SecurityException("Invalid token type. Expected: " + expectedType);
            }

            String jti = claims.getId();
            if (jti != null && blackList.isBlackListed(jti)) {
                throw new TokenRevokedException("Token has been revoked");
            }

            String userId = claims.getSubject();

            if (userId != null && blackList.isUserBanned(userId)) {
                throw new TokenRevokedException("User banned");
            }

            @SuppressWarnings("unchecked")
            List<String> roles = claims.get("roles", List.class);

            java.util.Map<String, Object> customClaims = new java.util.HashMap<>(claims);

            customClaims.remove(Claims.SUBJECT);
            customClaims.remove(Claims.EXPIRATION);
            customClaims.remove(Claims.ISSUED_AT);
            customClaims.remove(Claims.ID);
            customClaims.remove(Claims.ISSUER);
            customClaims.remove(Claims.AUDIENCE);
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
            Claims claims = jwtParser
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