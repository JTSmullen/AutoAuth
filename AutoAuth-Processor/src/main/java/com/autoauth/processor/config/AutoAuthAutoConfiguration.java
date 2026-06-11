package com.autoauth.processor.config;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@AutoConfiguration
@EnableConfigurationProperties(AutoAuthProperties.class)
public class AutoAuthAutoConfiguration {}
