package acdd.test.firsttest.common.util;

import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtUtil {
    
    private final SecretKey secretKey;
    private static final long EXPIRATION_TIME = 86400000; // 24 hours

    public JwtUtil() {
        // Updated for JJWT 0.12.x: Use standard HS256 key generation
        this.secretKey = Jwts.SIG.HS256.key().build();
    }

    public String generateToken(String userId, String username) {
        return Jwts.builder()
                .subject(userId)
                .claim("username", username)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(secretKey) // Algorithm inferred from key
                .compact();
    }

    public String getUserIdFromToken(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }
}
