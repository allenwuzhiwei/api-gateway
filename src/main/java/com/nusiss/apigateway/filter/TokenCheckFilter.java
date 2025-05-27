package com.nusiss.apigateway.filter;

import com.nusiss.apigateway.config.RedisCrudService;
import com.nusiss.apigateway.exception.CustomException;
import com.nusiss.apigateway.util.JwtUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class TokenCheckFilter implements GlobalFilter, Ordered {

    @Autowired
    private JwtUtils jwtUtils;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String token = exchange.getRequest().getHeaders().getFirst("Authorization");
        String uri = exchange.getRequest().getURI().toString();
        if (!uri.contains("/validateUserAndPassword")
                && !uri.contains("/login")
                && !uri.contains("/validateToken")
                && !uri.contains("swagger")) {
            if (StringUtils.isNotBlank(token) && token.startsWith("Bearer ")) {
                token = token.substring(7);
            }
            if(!jwtUtils.isValid(token)){
                throw new CustomException("Invalid token.");
            }
        }

        // continue the chain
        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return -1; // high precedence
    }

}
