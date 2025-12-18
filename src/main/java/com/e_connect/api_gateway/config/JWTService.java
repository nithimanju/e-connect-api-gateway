package com.e_connect.api_gateway.config;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class JWTService {

  @Value("${jwt-secret}")
  private String SECRETE;

  public String generateToken( String userName, String paswordString, List<String> roles, Boolean isGuest, Long userId) {
    Map<String, Object> claims = new HashMap<>();
    claims.put(Constants.USER_NAME, userName);
    claims.put(Constants.PASSWORD, paswordString);
    claims.put(Constants.ROLES, roles);
    return createToken(claims, userName);
  }

  private String createToken(Map<String, Object> claims, String subject) {
    return Jwts.builder()
        .claims(claims)
        .subject(subject)
        .issuedAt(new Date())
        .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 30))
        .signWith(getSigningKey())
        .compact();
  }

  public String extractUsername(String token) {
    return extractClaim(token, Claims::getSubject);
  }

  public String extractUserPassord(String token) {
    return extractClaim(token, claims -> claims.get(Constants.PASSWORD, String.class));
  }

  public Long extractUserId(String token) {
    return extractClaim(token, claims -> claims.get(Constants.USER_ID, Long.class));
  }
  public Boolean extractGuest(String token) {
    return extractClaim(token, claims -> claims.get(Constants.IS_GUEST, Boolean.class));
  }

  @SuppressWarnings("unchecked")
  public List<String> extractUserRoles(String token) {
    return (List<String>) extractClaim(token, claims -> claims.get(Constants.ROLES));
  }

  private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
    final Claims claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
  }

  private Claims extractAllClaims(String token) {
    SecretKey key = getSigningKey();
    return Jwts.parser()
        .verifyWith(key)
        .build()
        .parseSignedClaims(token)
        .getPayload();
  }
  private SecretKey getSigningKey() {
    byte[] keyBytes = Decoders.BASE64.decode(SECRETE);
    return Keys.hmacShaKeyFor(keyBytes);
}

  public boolean isTokenExpired(String tokenString) {
    Date tokenExpiration = extractClaim(tokenString, Claims::getExpiration);
    return tokenExpiration.before(new Date());
  }

}
