package com.autoauth.jwt;

import com.autoauth.blacklist.TokenBlackList;
import com.autoauth.config.AutoAuthProperties;
import com.autoauth.exception.JwtValidationException;
import com.autoauth.exception.TokenRevokedException;
import com.autoauth.model.AutoAuthUser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Locator;
import io.jsonwebtoken.security.SignatureException;

import java.security.Key;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

public class JwtValidator {

    private static final Duration CLOCK_SKEW = Duration.ofSeconds(30);

    private final JwtKeyProvider keyProvider;
    private final TokenBlackList blackList;
    private final AutoAuthProperties properties;
    private final Clock clock;
    private final JwtParser jwtParser;

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    // DI constructor including clock now
    public JwtValidator(JwtKeyProvider keyProvider,
                        TokenBlackList blackList,
                        AutoAuthProperties properties,
                        Clock clock) {
        this.keyProvider = Objects.requireNonNull(keyProvider, "keyProvider must not be null");
        this.blackList = Objects.requireNonNull(blackList, "blackList must not be null");
        this.properties = Objects.requireNonNull(properties, "properties must not be null");
        this.clock = Objects.requireNonNull(clock, "clock must not be null");

        this.jwtParser = buildParser();
    }

    // default utc if rather internal clock
    public JwtValidator(JwtKeyProvider keyProvider, TokenBlackList blackList, AutoAuthProperties properties) {
        this(keyProvider, blackList, properties, Clock.systemUTC());
    }

    private JwtParser buildParser() {
        JwtParserBuilder builder = Jwts.parser()
                // inject clock + build the skew
                .clock(() -> Date.from(clock.instant()))
                .clockSkewSeconds(CLOCK_SKEW.toSeconds())
                // get and validate kid
                .keyLocator(new Locator<Key>() {
                    @Override
                    public Key locate(io.jsonwebtoken.Header header) {
                        String kid = (header instanceof io.jsonwebtoken.JwsHeader jwsHeader) ? jwsHeader.getKeyId() : null;
                        PublicKey key = (kid != null && !kid.isBlank())
                                ? keyProvider.getPublicKey(kid)
                                : keyProvider.getPublicKey();

                        if (key == null) {
                            throw new SignatureException("No matching verification key found for token");
                        }
                        return key;
                    }
                });

        if (properties.getIssuer() != null && !properties.getIssuer().isBlank()) {
            builder.requireIssuer(properties.getIssuer());
        }

        if (properties.getAudience() != null && !properties.getAudience().isBlank()) {
            builder.requireAudience(properties.getAudience());
        }

        return builder.build();
    }

    /**
     * Helper token 'types' validators
     */
    public AutoAuthUser validateAccessToken(String token) {
        return validateAndExtractUser(token, "access");
    }

    public AutoAuthUser validateRefreshToken(String token) {
        return validateAndExtractUser(token, "refresh");
    }

    public AutoAuthUser validateTaskToken(String token) {
        return validateAndExtractUser(token, "task");
    }

    public AutoAuthUser validateAndExtractUser(String token, String expectedType) {
        if (token == null || token.isBlank()) {
            throw new JwtValidationException("JWT string must not be null or blank");
        }

        preValidateJwtHeader(token);

        try {

            Jws<Claims> jws = jwtParser.parseSignedClaims(token);
            Claims claims = jws.getPayload();

            // validates token signing was with a valid algo
            verifyHeaderAlgorithm(jws.getHeader().getAlgorithm());

            // pull token type for
            String tokenType = claims.get("type", String.class);
            // needs valid token type or rejected
            if (tokenType == null || !expectedType.equalsIgnoreCase(tokenType)) {
                throw new JwtValidationException(
                        String.format("Invalid token type. Expected: '%s', got: '%s'", expectedType, tokenType)
                );
            }

            // check for valid jti
            String jti = claims.getId();

            // must have jti for security
            if (jti == null || jti.isBlank()) {
                throw new JwtValidationException("Token missing mandatory 'jti' claim");
            }
            // check if jti is in banned cache
            if (blackList.isBlackListed(jti)) {
                throw new TokenRevokedException("Token has been revoked");
            }

            // get user id from jwt + validate subject claim on token
            String userId = claims.getSubject();

            if (userId == null || userId.isBlank()) {
                throw new JwtValidationException("Token missing mandatory 'sub' claim");
            }
            if (blackList.isUserBanned(userId)) {
                throw new TokenRevokedException("User has been banned");
            }

            // pull out roles from jwt
            @SuppressWarnings("unchecked")
            List<String> roles = claims.get("roles", List.class);
            List<String> safeRoles = (roles != null) ? List.copyOf(roles) : List.of();

           // extract details from jwt
            Map<String, Object> customClaims = new HashMap<>(claims);
            customClaims.remove(Claims.SUBJECT);
            customClaims.remove(Claims.EXPIRATION);
            customClaims.remove(Claims.ISSUED_AT);
            customClaims.remove(Claims.NOT_BEFORE);
            customClaims.remove(Claims.ID);
            customClaims.remove(Claims.ISSUER);
            customClaims.remove(Claims.AUDIENCE);
            customClaims.remove("roles");
            customClaims.remove("type");

            return new AutoAuthUser(userId, safeRoles, customClaims);

        } catch (ExpiredJwtException e) {
            throw new JwtValidationException("Token has expired", e);
        } catch (TokenRevokedException e) {
            // rethrow error
            throw e;
        } catch (JwtException | IllegalArgumentException e) {
            throw new JwtValidationException("JWT validation failed: " + e.getMessage(), e);
        }
    }

    /**
     * Revoke token, cache the token invalidation + ttl for expiration
     * @param token to be invalidated
     */
    public void revokeToken(String token) {
        if (token == null || token.isBlank()) {
            return;
        }

        try {

            Claims claims = jwtParser.parseSignedClaims(token).getPayload();

            String jti = claims.getId();
            if (jti == null || jti.isBlank()) {
                throw new IllegalArgumentException("Token does not contain a JWT ID (jti) and cannot be revoked");
            }

            Date expiration = claims.getExpiration();
            if (expiration != null) {

                Instant expiresAt = expiration.toInstant();
                Instant now = clock.instant();

                if (expiresAt.isAfter(now)) {

                    Duration ttl = Duration.between(now, expiresAt);
                    blackList.add(jti, ttl);

                }
            }
        } catch (ExpiredJwtException ignored) {
            // if expired don't cache
        } catch (JwtException e) {
            throw new IllegalArgumentException("Invalid JWT provided for revocation: " + e.getMessage(), e);
        }
    }

    private void verifyHeaderAlgorithm(String headerAlg) {
        if (headerAlg == null || "none".equalsIgnoreCase(headerAlg)) {
            throw new JwtValidationException("Tokens with algorithm 'none' are rejected");
        }

        // match to ec or rsa algo
        PublicKey currentKey = keyProvider.getPublicKey();

        if (currentKey instanceof RSAPublicKey && !headerAlg.startsWith("RS") && !headerAlg.startsWith("PS")) {

            throw new JwtValidationException("Algorithm mismatch: expected RSA, got " + headerAlg);

        } else if (currentKey instanceof ECPublicKey && !headerAlg.startsWith("ES")) {

            throw new JwtValidationException("Algorithm mismatch: expected ECDSA, got " + headerAlg);

        }
    }

    private void preValidateJwtHeader(String token) {

        int firstDot = token.indexOf('.');
        int secondDot = token.indexOf('.', firstDot + 1);

        if (firstDot == -1 || secondDot == -1 || token.indexOf('.', secondDot + 1) != -1) {

            throw new JwtValidationException("Invalid JWT: Must have exactly 3 base64url segments");

        }

        String rawHeaderBase64 = token.substring(0, firstDot);

        try {

            byte[] decodedHeader = Base64.getUrlDecoder().decode(rawHeaderBase64);
            JsonNode headerJson = OBJECT_MAPPER.readTree(decodedHeader);

            JsonNode algNode = headerJson.get("alg");

            if (algNode == null || "none".equalsIgnoreCase(algNode.asText())) {
                throw new JwtValidationException("Tokens with algorithm 'none' are rejected");
            }

            JsonNode kidNode = headerJson.get("kid");

            if (kidNode != null && !kidNode.isNull() && !kidNode.asText().isBlank()) {

                String kid = kidNode.asText();

                if (keyProvider.getPublicKey(kid) == null) {
                    throw new JwtValidationException("Unknown Key ID (kid): " + kid);
                }
            }

        } catch (IllegalArgumentException e) {
            throw new JwtValidationException("Malformed JWT: Header contains invalid Base64url encoding", e);
        } catch (JwtValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new JwtValidationException("Malformed JWT header format", e);
        }

    }
}