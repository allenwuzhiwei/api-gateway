package com.nusiss.apigateway.filter;

import com.nusiss.apigateway.exception.CustomException;
import com.nusiss.apigateway.util.JwtUtils;
import com.nusiss.commonservice.config.ApiResponse;
import com.nusiss.commonservice.entity.User;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.http.HttpMessageConverters;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Set;

@Component
public class TokenCheckFilter implements GlobalFilter, Ordered {

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private JwtTokenService jwtTokenService;

    @Bean
    public HttpMessageConverters messageConverters() {
        return new HttpMessageConverters();
    }


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String token = exchange.getRequest().getHeaders().getFirst("Authorization");
        String authToken = exchange.getRequest().getHeaders().getFirst("Authorization");
        String uri = exchange.getRequest().getURI().toString();
        String path = exchange.getRequest().getPath().toString();
        if (!uri.contains("/validateUserAndPassword")
                && !uri.contains("/login")
                && !uri.contains("/validateToken")
                && !uri.contains("/api/user")
                && !uri.contains("swagger")
                && !uri.contains(".png")
                && !uri.contains(".jpg")) {
            if (StringUtils.isNotBlank(token) && token.startsWith("Bearer ")) {
                token = token.substring(7);
            }
            if (!jwtUtils.isValid(token)) {
                throw new CustomException("Invalid authentication token.");

            } else {
                ResponseEntity<ApiResponse<Boolean>> userResponse = jwtTokenService.checkPermission(authToken, path);
                Boolean haspermissions = userResponse.getBody().getData();
                if (haspermissions) {
                    chain.filter(exchange);
                } else {
                    String message = "No access for the resource.";
                    String body = String.format("{\"success\":false,\"message\":\"%s\"}", message);
                    DataBuffer buffer = exchange.getResponse()
                            .bufferFactory()
                            .wrap(body.getBytes());
                    exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);

                    return exchange.getResponse().writeWith(Mono.just(buffer));
                }
            }


        }

        // continue the chain
        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return 0;
    }
}