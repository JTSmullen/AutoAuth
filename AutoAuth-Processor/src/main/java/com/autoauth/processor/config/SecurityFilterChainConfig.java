package com.autoauth.processor.config;

import com.autoauth.processor.exception.AutoAuthAccessDeniedHandler;
import com.autoauth.processor.exception.AutoAuthAuthenticationEntryPoint;
import com.autoauth.processor.filter.JwtAuthenticationFilter;
import com.autoauth.processor.jwt.JwtValidator;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityFilterChainConfig {

    private final AutoAuthProperties properties;
    private final JwtValidator jwtValidator;

    public SecurityFilterChainConfig(AutoAuthProperties properties, JwtValidator jwtValidator) {
        this.properties = properties;
        this.jwtValidator = jwtValidator;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        AutoAuthAuthenticationEntryPoint entryPoint = new AutoAuthAuthenticationEntryPoint();
        AutoAuthAccessDeniedHandler deniedHandler = new AutoAuthAccessDeniedHandler();
        JwtAuthenticationFilter jwtFilter = new JwtAuthenticationFilter(jwtValidator);

        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(deniedHandler)
                )
                .authorizeHttpRequests(auth -> {
                    List<String> publicPaths = properties.getPublicPaths();

                    if (publicPaths != null && !publicPaths.isEmpty()) {
                        auth.requestMatchers(publicPaths.toArray(new String[0])).permitAll();
                    }

                    auth.anyRequest().authenticated();
                })

                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();

    }

    private CorsConfigurationSource corsConfigurationSource() {

        CorsConfiguration configuration = new CorsConfiguration();

        List<String> allowedOrigins = properties.getAllowedOrigins();

        if (allowedOrigins == null || allowedOrigins.isEmpty()) {
            configuration.setAllowedOrigins(List.of("*"));
        } else {
            configuration.setAllowedOrigins(allowedOrigins);
        }

        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;

    }

}
