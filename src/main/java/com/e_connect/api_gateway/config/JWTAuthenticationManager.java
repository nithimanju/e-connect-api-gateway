package com.e_connect.api_gateway.config;

import java.util.List;

import org.springframework.http.HttpCookie;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
@Log4j2
public class JWTAuthenticationManager
    implements ReactiveAuthenticationManager, WebFilter, ServerAuthenticationConverter {

  private final JWTService jwtService;

  @Override
  public Mono<Authentication> authenticate(Authentication authentication) throws AuthenticationException {
    log.warn("Came to JWT Filter Authentication Manager");
    return Mono.just(authentication);
  }

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    log.error("Came to JWT filter");
    List<HttpCookie> cookies = exchange.getRequest().getCookies().get("JWT-TOKEN");
    try {
      if (cookies != null && !cookies.isEmpty()) {
        String token = cookies.get(0).getValue();

        if (token != null && !jwtService.isTokenExpired(token)) {
          String username = jwtService.extractUsername(token);
          List<SimpleGrantedAuthority> authorities = jwtService.extractUserRoles(token).stream()
              .map(SimpleGrantedAuthority::new).toList();

          UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(username, null,
              authorities);
          return chain.filter(exchange)
              .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));
        }
      }
    } catch (Exception e) {
      ResponseCookie cookie = ResponseCookie.from("JWT-TOKEN").path("/").httpOnly(true).maxAge(0).build();
      SecurityContextHolder.clearContext();
      exchange.getResponse().addCookie(cookie);
    }
    return chain.filter(exchange);
  }

  @Override
  public Mono<Authentication> convert(ServerWebExchange exchange) {
    ServerHttpRequest request = exchange.getRequest();
    List<HttpCookie> cookies = request.getCookies().get("JWT-TOKEN");
    try {
      if (cookies != null && !cookies.isEmpty()) {
        String token = cookies.get(0).getValue();

        if (token != null && !token.isEmpty()) {
          return Mono.just(new UsernamePasswordAuthenticationToken(null, token));
        }
      }
    } catch (Exception e) {
      ResponseCookie cookie = ResponseCookie.from("JWT-TOKEN").httpOnly(true).maxAge(0).build();
      SecurityContextHolder.clearContext();
      exchange.getResponse().addCookie(cookie);
    }

    return Mono.empty();
  }
}