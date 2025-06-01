package com.ijse.bookstore.security;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component
public class JwtUtils {

    public JwtUtils(
            @Value("${app.jwtSecret}") String jwtSecret,
            @Value("${app.jwtExpiration}") int jwtExpiration
    ) {
        this.jwtSecret = jwtSecret;
        this.jwtExpiration = jwtExpiration;
    }

    private final String jwtSecret;

    private final int jwtExpiration;

    public String generationJwtToken(Authentication authentication) {
        UserDetails userPrincipal = (UserDetails) authentication.getPrincipal();

        return Jwts.builder()
                .setSubject(userPrincipal.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(new Date().getTime() + jwtExpiration))
                .signWith(key(), SignatureAlgorithm.HS256)
                .compact();
    }

    public Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64URL.decode(jwtSecret));
    }

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    public boolean validateJwtToken(String authToken) {

        try {
            Jwts.parserBuilder().setSigningKey(key()).build().parse(authToken);

            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT Token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("Token expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("Token not supported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("Token is empty: {}", e.getMessage());
        }

        return false;
    }

    public String getUsernameFromJwt(String authToken) {

        return Jwts.parserBuilder().setSigningKey(key()).build().parseClaimsJws(authToken).getBody().getSubject();
    }
}
