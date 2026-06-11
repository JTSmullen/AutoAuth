package com.autoauth.processor.model;

import java.util.List;

/**
  *  User data that is extracted from or injected into the JWT
  */

public record AutoAuthUser (
  String userId,
  List<String> roles
)
{}
