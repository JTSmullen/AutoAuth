package com.autoauth.model;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 *  User data that is extracted from or injected into the JWT
 */

public record AutoAuthUser (
        String userId,
        List<String> roles,
        Map<String, Object> customClaims
){

    public AutoAuthUser {
        if (roles == null) {
            roles = Collections.emptyList();
        }

        if (customClaims == null) {
            customClaims = Collections.emptyMap();
        }
    }

}