package com.feddoubt.cry.filter;

import com.feddoubt.common.config.jwt.JwtProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    private final JwtProvider jwtProvider;
    private final ServiceFilter serviceFilter;

    public SecurityConfig(JwtProvider jwtProvider, ServiceFilter serviceFilter) {
        this.jwtProvider = jwtProvider;
        this.serviceFilter = serviceFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable()) //  正確方式關閉 CSRF
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/api/v1/auth/login",
                                "/api/v1/auth/token",
                                "/api/v1/cry/**",
                                "/api/v1/key/public"
                        ).permitAll() // 允許這些路徑不需要認證
                        .requestMatchers("/hi").permitAll()  // 添加測試 endpoint 例外
                        .requestMatchers(
                                "/swagger-ui.html",
                                "/swagger-ui/**",
                                "/v3/api-docs/**",
                                "/swagger-resources/**",
                                "/webjars/**"
                        ).permitAll()
                        .anyRequest().authenticated() // 其他 API 需要驗證
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // 無狀態，使用 JWT
                .addFilterBefore(serviceFilter, UsernamePasswordAuthenticationFilter.class); // 加入 JWT 過濾器

        return http.build();
    }
}
