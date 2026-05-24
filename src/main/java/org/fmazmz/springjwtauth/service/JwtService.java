package org.fmazmz.springjwtauth.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.fmazmz.springjwtauth.model.Scope;
import org.fmazmz.springjwtauth.model.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Duration;
import java.util.Date;
import java.util.List;

@Service
public class JwtService {

    @Value("${auth.jwt.signing-key}")
    private String secret;
    @Value("${auth.jwt.issuer}")
    private String issuer;
    @Value("${auth.jwt.audience}")
    private String audience;
    @Value("${auth.jwt.access-token-ttl}")
    private Duration tokenTtl;

    private SecretKey signingKey() {
        return Keys.hmacShaKeyFor(secret.getBytes());
    }

    public Claims extractClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(signingKey())
                .requireIssuer(issuer)
                .requireAudience(audience)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String extractUsername(String token) {
        return extractClaims(token).getSubject();
    }

    public boolean isTokenValid(String token) {
        Claims claims = extractClaims(token);
        return claims.getExpiration().after(new Date());
    }

    public String generateToken(User user) {
        return Jwts.builder()
                .setSubject(user.getUsername())
                .setAudience(audience)
                .setIssuer(issuer)
                .claim("scope", Scope.forRole(user.getRole()))
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + tokenTtl.toMillis()))
                .signWith(signingKey())
                .compact();
    }

    public List<GrantedAuthority> extractScopeAuthorities(String token) {
        Object scopeClaim = extractClaims(token).get("scope");
        if (!(scopeClaim instanceof List<?> scopes)) {
            return List.of();
        }
        return scopes.stream()
                .map(Object::toString)
                .<GrantedAuthority>map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
                .toList();
    }
}