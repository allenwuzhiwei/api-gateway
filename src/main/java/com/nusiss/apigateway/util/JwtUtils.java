package com.nusiss.apigateway.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nusiss.apigateway.config.RedisCrudService;
import com.nusiss.apigateway.exception.CustomException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtils {

    private final String secret = "mySuperSecureSecretKeyThatIs32Bytes!";
    private final SecretKey key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private RedisCrudService redisCrudService;

    public JwtUtils(){

    }

    public String generateToken(String userName) {
        return Jwts.builder()
                .setSubject(userName)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) // 1 hour
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public String extractUserName(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public String getCurrentUsername(HttpServletRequest request){
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7); // Remove "Bearer "
            return extractUserName(token);
        }

        throw new CustomException("No token.");
    }

    /*public User getCurrentUserInfo(HttpServletRequest request){
        String username = "";
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7); // Remove "Bearer "
            username = extractUserName(token);
        }
        if(redisCrudService.exists(username)){
            String userJson = redisCrudService.get(username);
            try {
                User user = objectMapper.readValue(userJson, User.class);
                return user;
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        } else {
            throw new CustomException("Fail to get user info: user didn't login");
        }
    }*/

    public boolean isValid(String token) {
        try {
            String username = extractUserName(token);

            return redisCrudService.exists(username);
        } catch (Exception e) {
            return false;
        }
    }
}
