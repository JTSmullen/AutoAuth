package com.autoauth.processor.model;

import java.util.List;
import java.util.Map;

/**
  *  User data that is extracted from or injected into the JWT
  */

public record AutoAuthUser (
  String userId,
  List<String> roles,
  Map<String, Object> customClaims
)
{

    public AutoAuthUser(String userId, List<String> roles) {
        this(userId, roles, Map.of());
    }

}
