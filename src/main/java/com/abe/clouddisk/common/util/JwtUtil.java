package com.abe.clouddisk.common.util;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

/**
 * Utility class for JSON Web Token (JWT) generation and validation.
 */
@Slf4j
@Getter
@Component
public class JwtUtil {
    
    /**
     * The secret key used to sign and verify JWT tokens.
     */
    private final SecretKey secretKey;

    /**
     * The expiration time for the JWT token in milliseconds (24 hours).
     */
    private static final long EXPIRATION_TIME = 86400000; // 24 hours

    /**
     * Constructs a new JwtUtil with a generated secret key.
     */
    public JwtUtil() {
        // Updated for JJWT 0.12.x: Use standard HS256 key generation
        this.secretKey = Jwts.SIG.HS256.key().build();
    }

    /**
     * Generates a JWT token for the specified user.
     *
     * @param userId   the unique identifier of the user
     * @param username the username of the user
     * @return the generated JWT token
     */
    public String generateToken(String userId, String username) {
        return Jwts.builder()
                .subject(userId)
                .claim("username", username)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(secretKey) // Algorithm inferred from key
                .compact();
    }

    /**
     * Extracts the user ID from the specified JWT token.
     *
     * @param token the JWT token to parse
     * @return the user ID extracted from the token, or null if validation fails
     */
    public String getUserIdFromToken(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .getSubject();
        } catch (ExpiredJwtException e) {
            log.warn("JWT token has expired: {}", e.getMessage());
        } catch (SignatureException e) {
            log.warn("JWT signature validation failed: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            log.warn("Invalid JWT token format: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.warn("Unsupported JWT token: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.warn("JWT token is null or empty: {}", e.getMessage());
        } catch (JwtException e) {
            log.error("JWT processing failed: {}", e.getMessage());
        }
        return null;
    }

}
