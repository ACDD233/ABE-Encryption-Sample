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
