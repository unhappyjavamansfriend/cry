package com.feddoubt.cry.filter;

import com.feddoubt.common.config.jwt.JwtProvider;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.UUID;

@Slf4j
@Component
public class ServiceFilter extends OncePerRequestFilter {
    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtProvider jwtProvider;

    public ServiceFilter(JwtProvider jwtProvider){
        this.jwtProvider = jwtProvider;
    }

    @Override
    protected void doFilterInternal(jakarta.servlet.http.HttpServletRequest request, HttpServletResponse response, jakarta.servlet.FilterChain filterChain) throws jakarta.servlet.ServletException, IOException {
        String path = request.getRequestURI();
        String method = request.getMethod();

        log.info("====== Filter Start ======");
        log.info("Request URI: {}", path);
        log.info("Request Method: {}", method);
        log.info("Request Headers: {}", Collections.list(request.getHeaderNames()));


        try {
            if (path.contains("/swagger-ui") || path.contains("/v3/api-docs")) {
                log.info("Processing Swagger request: {}", path);
                filterChain.doFilter(request, response);
                log.info("Swagger request processed: {} - Status: {}", path, response.getStatus());
                return;
            }
            // ... 其他邏輯 ...
        } catch (Exception e) {
            log.error("Error processing request: " + path, e);
            throw e;
        }

        try {


            if (path.contains("/api/v1/auth/token")) {
                log.info("get auth token");
                filterChain.doFilter(request, response);
            }

            if (path.contains("/api/v1/key/public") || path.contains("/api/v1/cry")) {
                String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
                log.info("authHeader: {}", authHeader);

                if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
                    log.warn("缺少或無效的 Authorization Header");
                    sendUnauthorizedResponse(response, "Missing or invalid Authorization header");
                    return;
                }

                String jwtToken = getJwtToken(authHeader);
                if (jwtToken == null) {
                    log.warn("JWT 解析失敗");
                    sendUnauthorizedResponse(response, "Invalid JWT token");
                    return;
                }
                log.warn("jwtToken:{}",jwtToken);

                String userId = jwtProvider.extractUsername(jwtToken);
                log.warn("userId:{}",userId);

                if (userId == null) {
                    log.warn("JWT 無法解析 User ID");
                    sendUnauthorizedResponse(response, "Invalid JWT token");
                    return;
                }

                log.info("JWT 驗證成功, userId: {}", userId);
                log.info("Before chain.doFilter");
                filterChain.doFilter(request, response);
                log.info("After chain.doFilter");
            }


        } catch (ExpiredJwtException e) {
            log.info("Token 已過期，重新生成中...");
            // 取得過期 Token 的使用者資訊（如果 JWT 有儲存 userId，可解析出來）
//            String expiredToken = request.getHeader(AUTHORIZATION_HEADER);
            String userId = UUID.randomUUID().toString(); // 無法解析時，使用隨機 UUID

            // 重新生成 Token
            String newToken = jwtProvider.generateToken(userId);
            log.info("新 Token 生成完成: {}", newToken);

            // 將新 Token 設置到 Response Header
            response.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + newToken);

            // 重新執行請求
            filterChain.doFilter(request, response);

        } catch (Exception e) {
            log.error("Filter error", e);
            sendUnauthorizedResponse(response, "Authentication error");
        } finally {
            log.info("離開 ServiceFilter - URL: {}", request.getRequestURI());
        }

    }

    private String getJwtToken(String header) {

        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }

        return null;
    }

    private void sendUnauthorizedResponse(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\": \"" + message + "\"}");
    }
}