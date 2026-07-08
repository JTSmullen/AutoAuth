package com.autoauth.controller;

import com.autoauth.annotation.PublicEndpoint;
import com.autoauth.jwt.JwtKeyProvider;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@RestController
public class JwksController {

    private final JwtKeyProvider keyProvider;

    public JwksController(JwtKeyProvider keyProvider) {
        this.keyProvider = keyProvider;
    }

    @PublicEndpoint
    @GetMapping("/.well-known/jwks.json")
    public ResponseEntity<Map<String, Object>> getJwks() {

        try {

            RSAPublicKey rsaPublicKey = (RSAPublicKey) keyProvider.getPublicKey();

            byte[] modulusBytes = rsaPublicKey.getModulus().toByteArray();
            if (modulusBytes[0] == 0) {
                byte[] temp = new byte[modulusBytes.length -1];
                System.arraycopy(modulusBytes, 1, temp, 0, temp.length);
                modulusBytes = temp;
            }

            byte[] exponentBytes = rsaPublicKey.getPublicExponent().toByteArray();

            String modulus = Base64.getUrlEncoder().withoutPadding().encodeToString(modulusBytes);
            String exponent = Base64.getUrlEncoder().withoutPadding().encodeToString(exponentBytes);

            Map<String, Object> jwk = Map.of(
                    "kty", "RSA",
                    "use", "sig",
                    "alg", "RS256",
                    "kid", keyProvider.getKid(),
                    "n", modulus,
                    "e", exponent
            );

            return ResponseEntity.ok()
                    .cacheControl(CacheControl.maxAge(1, TimeUnit.DAYS).cachePublic())
                    .body(Map.of("keys", List.of(jwk)));

        } catch (Exception e) {
            return ResponseEntity.ok()
                    .cacheControl(CacheControl.noCache())
                    .body(Map.of("keys", List.of()));
        }

    }

}
