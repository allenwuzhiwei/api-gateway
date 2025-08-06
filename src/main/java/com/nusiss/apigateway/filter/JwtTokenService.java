package com.nusiss.apigateway.filter;

import com.nusiss.commonservice.config.ApiResponse;
import com.nusiss.commonservice.entity.User;
import com.nusiss.commonservice.feign.UserFeignClient;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.ResponseEntity;

import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@Configuration
public class JwtTokenService {

    @Lazy
    @Autowired
    private UserFeignClient userFeignClient;

    // Secret key for signing the JWT. Keep this secure and don't expose it.
    public static final SecretKey SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS512);

    public static final DateTimeFormatter DATE_TIME_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public static  String generateToken(String username, String password) {
        // Get the current time
        LocalDateTime now = LocalDateTime.now();

        // Set expiration time to 30 minutes after the current time
        LocalDateTime expireDateTime = now.plusMinutes(30);

        // Convert expiration time to Date for JWT
        Date expirationDate = java.sql.Timestamp.valueOf(expireDateTime);

        // Convert expiration time to string for storing in JWT claims
        String expireDateTimeStr = expireDateTime.format(DATE_TIME_FORMATTER);

        // Add claims (custom fields like username, password, and expireDateTime)
        Map<String, Object> claims = new HashMap<>();
        claims.put("username", username);
        claims.put("password", password);

        // Build and sign the JWT token
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(new Date()) // Set issued time to now
                .setExpiration(expirationDate) // Set expiration to 30 minutes later
                .signWith(SECRET_KEY) // Sign with the secret key
                .compact();
    }

    public ResponseEntity<ApiResponse<User>> getCurrentUserInfoWithTokenString(String authToken){

        return userFeignClient.getCurrentUserInfoWithTokenString(authToken);
    }

    public ResponseEntity<ApiResponse<Integer>> getRoleByUserId(Integer userId){

        return userFeignClient.getRoleByUserId(userId);
    }

    public ResponseEntity<Set<String>> findPermissionsByUserId(Integer userId){

        return userFeignClient.findPermissionsByUserId(userId);
    }

    /*public ResponseEntity<ApiResponse<User>> findByUsername(String userName){

        return userFeignClient.findByUsername(userName);
    }*/

}
