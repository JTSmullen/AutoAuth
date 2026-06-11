package com.autoauth.processor.annotation;

import com.autoauth.processor.config.AutoAuthAutoConfiguration;
import org.springframework.context.annotation.Import;
import java.lang.annotation.*;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(AutoAuthAutoConfiguration.class)
public @interface EnableAutoAuth {}
