package com.autoauth.config;

import org.springdoc.core.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AutoAuthSwaggerConfig {

    @Bean
    public GroupedOpenApi autoAuthApi() {
        return GroupedOpenApi.builder()
                .group("autoauth")
                .pathsToMatch("/**")
                .build();
    }
}
