package com.abe.clouddisk.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * Configuration class for application security settings.
 * Uses Spring Security to define access control rules and authentication mechanisms.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * Configures the security filter chain to permit all requests and disable common security features
     * like CSRF, form login, and HTTP Basic authentication for the prototype.
     *
     * @param http the HttpSecurity object to configure
     * @return the configured security filter chain
     * @throws Exception if an error occurs during configuration
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .formLogin(AbstractHttpConfigurer::disable)
            .httpBasic(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth
                .anyRequest().permitAll()
            );
        return http.build();
    }

    /**
     * Provides an in-memory user details service.
     * An empty implementation is used to prevent Spring Security from generating a default password.
     *
     * @return an empty InMemoryUserDetailsManager
     */
    @Bean
    public UserDetailsService userDetailsService() {
        // Providing an empty In-Memory UserDetailsManager stops Spring from generating a default password
        return new InMemoryUserDetailsManager();
    }
}
