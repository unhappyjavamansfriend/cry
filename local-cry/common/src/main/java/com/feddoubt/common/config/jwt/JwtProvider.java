package com.feddoubt.common.config.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Slf4j
@Component
public class JwtProvider {

    @Value("${jwt.secret}")
    private String base64Secret;

	@Value("${jwt.ttl}")
	private long jwtExpiration;

    @PostConstruct
    public void init() {
        log.info("JwtProvider initialized, base64Secret: {}", base64Secret);
        if (base64Secret == null || base64Secret.isEmpty()) {
            throw new RuntimeException("JWT Secret 未正確讀取！");
        }
    }

    @PreDestroy
    public void destroy() {
        log.info("JwtProvider being destroyed, base64Secret: {}", base64Secret);
    }

    public Key getBase64Secret() {
        try {
            log.info("JwtProvider base64Secret:{}",base64Secret);
            byte[] decodedKey = Base64.getDecoder().decode(base64Secret);
//            log.info("decodedKey:{}",decodedKey);
            return Keys.hmacShaKeyFor(decodedKey);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("JWT Secret 格式錯誤，請確保是 Base64 編碼", e);
        }
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        Date expiration = new Date(System.currentTimeMillis() + 60 * 60 * 1000); //1hr
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    public long getExpirationTime() {
        return jwtExpiration;
    }

    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expiration
    ) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getBase64Secret(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateToken(String uuid) {
        return buildToken(new HashMap<>(), uuid ,jwtExpiration);
    }

    private String buildToken(
            Map<String, Object> extraClaims,
            String uuid,
            long expiration
    ) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(uuid)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getBase64Secret(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getBase64Secret())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // getSubject 測試用
    public String extractSubject(String token) {
        log.info("token:{}", token);
        Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(getBase64Secret())
                .build()
                .parseClaimsJws(token)
                .getBody();
        String base64Secret = this.base64Secret;
        log.info("base64Secret:{}", base64Secret);
        String subject = claims.getSubject();
        log.info("subject:{}", subject);
        return claims.getSubject();
    }

}