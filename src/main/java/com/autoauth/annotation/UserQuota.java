package com.autoauth.annotation;

import java.lang.annotation.*;

@Target({})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface UserQuota {

    String role();
    int MaxRequests();

}
