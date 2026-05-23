package org.fmazmz.springjwtauth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class JwtService {

    private final String SECRET = "signing-key";

    public Claims extractClaims(String token) {
        return Jwts.parserBuilder()
                // RSA / HMAC?
                .setSigningKey(Keys.hmacShaKeyFor(SECRET.getBytes()))
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
}