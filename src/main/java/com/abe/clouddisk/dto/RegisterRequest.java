package com.abe.clouddisk.dto;

import lombok.Data;

/**
 * Data Transfer Object for user registration requests.
 */
@Data
public class RegisterRequest {
    /**
     * The desired username.
     */
    private String username;

    /**
     * The user's email address.
     */
    private String email;

    /**
     * The user's password.
     */
    private String password;
}
