/*
 * Copyright (C) 2026 ACDD233
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
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
