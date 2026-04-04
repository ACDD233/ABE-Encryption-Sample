package com.abe.clouddisk.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

/**
 * Entity representing a system user.
 */
@Setter
@Getter
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

}
