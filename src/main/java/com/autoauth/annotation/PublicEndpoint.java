package com.autoauth.annotation;

import java.lang.annotation.*;

// Maker annotation to say whether a specific controller or method should be accessible without JWT

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface PublicEndpoint {}