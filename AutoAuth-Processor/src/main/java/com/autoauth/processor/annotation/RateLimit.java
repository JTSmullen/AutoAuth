package com.autoauth.processor.annotation;

import java.lang.annotation.*;
import java.util.concurrent.TimeUnit;

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RateLimit {

    int requests();

    long window();

    TimeUnit unit() default TimeUnit.MINUTES;

}
