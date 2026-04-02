package com.abe.clouddisk.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import java.time.LocalDateTime;

/**
 * Entity representing a system user.
 */
@TableName("users")
public class User {
    /**
     * The unique identifier for the user.
     */
    @TableId(type = IdType.AUTO)
    private Integer id;

    /**
     * The unique username of the user.
     */
    private String username;

    /**
     * The email address of the user.
     */
    private String email;

    /**
     * The hashed password of the user.
     */
    private String passwordHash;

    /**
     * The ABE attributes assigned to the user, stored as a comma-separated string.
     */
    private String attributes;

    /**
     * The role of the user, e.g., "USER" or "ADMIN".
     */
    private String role; // "USER" or "ADMIN"

    /**
     * The timestamp when the user account was created.
     */
    private LocalDateTime createdAt;

    /**
     * Returns the user's role.
     * @return the role
     */
    public String getRole() {
        return role;
    }

    /**
     * Sets the user's role.
     * @param role the role to set
     */
    public void setRole(String role) {
        this.role = role;
    }

    /**
     * Returns the user ID.
     * @return the ID
     */
    public Integer getId() {
        return id;
    }

    /**
     * Sets the user ID.
     * @param id the ID to set
     */
    public void setId(Integer id) {
        this.id = id;
    }

    /**
     * Returns the username.
     * @return the username
     */
    public String getUsername() {
        return username;
    }

    /**
     * Sets the username.
     * @param username the username to set
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * Returns the email address.
     * @return the email
     */
    public String getEmail() {
        return email;
    }

    /**
     * Sets the email address.
     * @param email the email to set
     */
    public void setEmail(String email) {
        this.email = email;
    }

    /**
     * Returns the hashed password.
     * @return the password hash
     */
    public String getPasswordHash() {
        return passwordHash;
    }

    /**
     * Sets the hashed password.
     * @param passwordHash the password hash to set
     */
    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    /**
     * Returns the user's ABE attributes.
     * @return the attributes string
     */
    public String getAttributes() {
        return attributes;
    }

    /**
     * Sets the user's ABE attributes.
     * @param attributes the attributes string to set
     */
    public void setAttributes(String attributes) {
        this.attributes = attributes;
    }

    /**
     * Returns the creation timestamp.
     * @return the creation timestamp
     */
    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    /**
     * Sets the creation timestamp.
     * @param createdAt the creation timestamp to set
     */
    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }
}
