package com.fedoubt.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsConfig {
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/api/**")
                        .allowedOrigins("*")
                        .allowedMethods("GET", "POST", "OPTIONS")  // Match API Gateway methods
                        .allowedHeaders("Content-Type", "Authorization", "X-Amz-Date",
                                "X-Api-Key", "X-Amz-Security-Token")
                        .exposedHeaders("Access-Control-Allow-Origin",
                                "Access-Control-Allow-Methods")
                        .maxAge(3600);  // Cache preflight for 1 hour
            }
        };
    }
}