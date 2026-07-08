package com.autoauth.annotation;

import java.lang.annotation.*;
import java.util.concurrent.TimeUnit;

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RateLimit {

    UserQuota[] value() default{};

    int fallbackRequests() default 5;

    long window() default 1;

    TimeUnit unit() default TimeUnit.MINUTES;

}