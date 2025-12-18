package com.e_connect.api_gateway.config;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.ResponseCookie;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.server.WebFilter;

import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

  private final JWTAuthenticationManager jwtAuthenticationManager;

  @Value("${cors-url}")
  private String corsUrl; 

  @Value("${allowable-path-machers}")
  private String pathMatchers;
  @Bean
  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
    System.out.println(corsUrl);
    http
        .cors(cors -> cors.configurationSource(
            request -> {
              var corsConfiguration = new CorsConfiguration();
              corsConfiguration.setAllowedOrigins(Arrays.asList(corsUrl.split(",")));
              corsConfiguration.setAllowedMethods(
                  List.of(Constants.GET, Constants.POST, Constants.PUT, Constants.DELETE, Constants.OPTIONS));
              corsConfiguration.setAllowedHeaders(List.of("*"));
              corsConfiguration.setAllowCredentials(true);
              return corsConfiguration;
            }))
        .authorizeExchange(ex -> ex
            .pathMatchers(pathMatchers.split(","))
            .permitAll()
            .anyExchange().authenticated())
        .authenticationManager(jwtAuthenticationManager)
        .addFilterAt(jwtAuthenticationManager, SecurityWebFiltersOrder.AUTHENTICATION)
        .addFilterAfter(csrfCookieWebFilter(), SecurityWebFiltersOrder.LAST)
        .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
        .csrf((csrf) -> csrf.csrfTokenRequestHandler(new ServerCsrfTokenRequestAttributeHandler())
            .csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse()));

    return http.build();
  }

  @Bean
  public WebFilter csrfCookieWebFilter() {
    return (exchange, chain) -> {
      Mono<CsrfToken> csrfTokenMono = exchange.getAttribute(CsrfToken.class.getName());
      if (csrfTokenMono == null) {
        return chain.filter(exchange);
      }
      return csrfTokenMono
          .doOnSuccess(token -> {
            ResponseCookie cookie = ResponseCookie.from(Constants.XSRF_TOKEN, token.getToken())
                .httpOnly(false)
                .secure(false)
                .path(Constants.FORWARD_SLASH)
                .maxAge(4000)
                .build();
            exchange.getResponse().addCookie(cookie);
          })
          .then(chain.filter(exchange));
    };
  }
}
