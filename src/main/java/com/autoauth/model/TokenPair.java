package com.autoauth.model;

public record TokenPair(
        String accessToken,
        String refreshToken
) {}
