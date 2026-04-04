package com.abe.clouddisk.common.util;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
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
     * Constructs a new JwtUtil. 
     * If a secret is provided in properties, it is used. Otherwise, a random key is generated.
     * 
     * @param secret the secret key string from properties
     */
    public JwtUtil(@Value("${jwt.secret:}") String secret) {
        if (secret == null || secret.isBlank()) {
            log.info("No JWT secret provided in configuration. Generating a random key for this session.");
            this.secretKey = Jwts.SIG.HS256.key().build();
        } else {
            log.info("Using JWT secret from configuration.");
            byte[] keyBytes;
            try {
                // Try to decode as Base64 first
                keyBytes = Decoders.BASE64.decode(secret);
            } catch (Exception e) {
                // If not Base64, use raw UTF-8 bytes
                keyBytes = secret.getBytes(StandardCharsets.UTF_8);
            }
            
            // Validate key length for HS256 (minimum 256 bits / 32 bytes)
            if (keyBytes.length < 32) {
                log.error("The configured JWT secret is too short (less than 32 bytes). " +
                        "HS256 requires at least 256 bits. Falling back to a random key.");
                this.secretKey = Jwts.SIG.HS256.key().build();
            } else {
                this.secretKey = Keys.hmacShaKeyFor(keyBytes);
            }
        }
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
