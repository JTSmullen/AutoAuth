package com.autoauth.processor.model;

public record TokenPair(
        String accessToken,
        String refreshToken
) {}
