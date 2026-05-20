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
 * Entity representing an attribute in the system catalog.
 * Attributes are used in Attribute-Based Encryption (ABE) policies.
 */
@Setter
@Getter
@TableName("attributes_catalog")
public class AttributeCatalog {

    /**
     * The unique identifier for the attribute.
     */
    @TableId(type = IdType.AUTO)
    private Integer id;

    /**
     * The name of the attribute (e.g., "DEPARTMENT_HR").
     */
    private String name;

    /**
     * A brief description of the attribute's purpose.
     */
    private String description;

    /**
     * The timestamp when the attribute was created.
     */
    private LocalDateTime createdAt;

}
