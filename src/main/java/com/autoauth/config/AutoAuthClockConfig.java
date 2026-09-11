package com.autoauth.config;


import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

@Configuration
public class AutoAuthClockConfig {

    @Bean
    @ConditionalOnMissingBean(Clock.class)
    public Clock autoAuthClock() {
        return Clock.systemUTC();
    }

}
