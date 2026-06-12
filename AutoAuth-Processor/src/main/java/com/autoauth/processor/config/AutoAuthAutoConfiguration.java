package com.autoauth.processor.config;

import com.autoauth.processor.jwt.JwtGenerator;
import com.autoauth.processor.jwt.JwtKeyProvider;
import com.autoauth.processor.jwt.JwtValidator;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

import java.security.NoSuchAlgorithmException;

@AutoConfiguration
@EnableConfigurationProperties(AutoAuthProperties.class)
@Import(SecurityFilterChainConfig.class)
public class AutoAuthAutoConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public JwtKeyProvider JwtKeyProvider(AutoAuthProperties properties) throws NoSuchAlgorithmException {
    return new JwtKeyProvider(properties);
  }

  @Bean
  @ConditionalOnMissingBean
  public JwtGenerator jwtGenerator(JwtKeyProvider keyProvider, AutoAuthProperties properties) {
    return new JwtGenerator(keyProvider, properties);
  }

  @Bean
  @ConditionalOnMissingBean
  public JwtValidator jwtValidator(JwtKeyProvider keyProvider) {
    return new JwtValidator(keyProvider);
  }
  
}
