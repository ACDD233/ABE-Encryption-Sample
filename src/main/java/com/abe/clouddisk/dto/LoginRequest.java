package com.abe.clouddisk.dto;

import lombok.Data;

/**
 * Data Transfer Object for user login requests.
 */
@Data
public class LoginRequest {
    /**
     * The user's email address.
     */
    private String email;

    /**
     * The user's password.
     */
    private String password;
}
