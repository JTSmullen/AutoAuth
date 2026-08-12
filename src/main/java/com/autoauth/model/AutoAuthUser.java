package com.autoauth.model;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 *  User data that is extracted from or embedded into the JWT <br>
 *
 *  userId is a required type, roles and customClaims are null by default
 */
public record AutoAuthUser (
        String userId,
        List<String> roles,
        Map<String, Object> customClaims
){

    // ensure no null errors
    public AutoAuthUser {
        if (roles == null) {
            roles = Collections.emptyList();
        }

        if (customClaims == null) {
            customClaims = Collections.emptyMap();
        }
    }

}