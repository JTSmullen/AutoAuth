package com.autoauth.model;

/**
 * Users must have access tokens and refresh tokens to resign access tokens
 *
 * @param accessToken
 * @param refreshToken
 */
public record TokenPair(
        String accessToken,
        String refreshToken
) {}
