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

import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import com.baomidou.mybatisplus.annotation.IdType;
import lombok.Getter;
import lombok.Setter;

/**
 * Entity representing the ABE secret key assigned to a user.
 */
@Setter
@Getter
@TableName("user_keys")
public class UserKey {

    /**
     * The ID of the user who owns this secret key.
     */
    @TableId(type = IdType.INPUT)
    private Integer userId;

    /**
     * The 'D' component of the user's ABE secret key.
     */
    private byte[] skD;

    /**
     * The 'Dr' component of the user's ABE secret key.
     */
    private byte[] skDr;

}
