package com.autoauth.processor.config;

import com.autoauth.processor.aop.RateLimitAspect;
import com.autoauth.processor.blacklist.CafeTokenBlackList;
import com.autoauth.processor.blacklist.TokenBlackList;
import com.autoauth.processor.controller.JwksController;
import com.autoauth.processor.exception.AutoAuthRateLimitExceptionResolver;
import com.autoauth.processor.jwt.JwtGenerator;
import com.autoauth.processor.jwt.JwtKeyProvider;
import com.autoauth.processor.jwt.JwtValidator;
import com.autoauth.processor.aop.RoleAspect;
import com.autoauth.processor.config.AutoAuthSwaggerConfig;

import com.autoauth.processor.ratelimit.RateLimitService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.EnableAspectJAutoProxy;

import java.security.NoSuchAlgorithmException;

@AutoConfiguration
@EnableConfigurationProperties(AutoAuthProperties.class)
@Import({SecurityFilterChainConfig.class, AutoAuthSwaggerConfig.class})
@EnableAspectJAutoProxy
public class AutoAuthAutoConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public JwtKeyProvider JwtKeyProvider(AutoAuthProperties properties) throws NoSuchAlgorithmException {
    return new JwtKeyProvider(properties);
  }

  @Bean
  @ConditionalOnMissingBean
  public RoleAspect roleAspect() {
    return new RoleAspect();
  }

  @Bean
  @ConditionalOnMissingBean
  public JwtGenerator jwtGenerator(JwtKeyProvider keyProvider, AutoAuthProperties properties) {
    return new JwtGenerator(keyProvider, properties);
  }

  @Bean
  @ConditionalOnMissingBean(TokenBlackList.class)
  public TokenBlackList tokenBlackList() {
    return new CafeTokenBlackList();
  }

  @Bean
  @ConditionalOnProperty(name = "autoauth.public-key")
  public JwksController jwksController(JwtKeyProvider keyProvider) {
    return new JwksController(keyProvider);
  }

  @Bean
  @ConditionalOnMissingBean
  public JwtValidator jwtValidator(JwtKeyProvider keyProvider, TokenBlackList blackList) {
    return new JwtValidator(keyProvider, blackList);
  }

  @Bean
  @ConditionalOnMissingBean
  public RateLimitService rateLimitService() {
    return new RateLimitService();
  }

  @Bean
  @ConditionalOnMissingBean
  public RateLimitAspect rateLimitAspect(RateLimitService rateLimitService) {
    return new RateLimitAspect(rateLimitService);
  }

  @Bean
  @ConditionalOnMissingBean
  public AutoAuthRateLimitExceptionResolver autoAuthRateLimitExceptionResolver() {
    return new AutoAuthRateLimitExceptionResolver();
  }
  
}
