package com.autoauth.annotation;

import com.autoauth.config.AutoAuthAutoConfiguration;
import org.springframework.context.annotation.Import;
import java.lang.annotation.*;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(AutoAuthAutoConfiguration.class)
public @interface EnableAutoAuth {}
