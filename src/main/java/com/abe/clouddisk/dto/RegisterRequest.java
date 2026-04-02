package com.abe.clouddisk.dto;

/**
 * Data Transfer Object for user registration requests.
 */
public class RegisterRequest {
    /**
     * The desired username.
     */
    public String username;

    /**
     * The user's email address.
     */
    public String email;

    /**
     * The user's password.
     */
    public String password;
}
