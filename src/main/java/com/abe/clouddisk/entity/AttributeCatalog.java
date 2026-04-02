package com.abe.clouddisk.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import java.time.LocalDateTime;

/**
 * Entity representing an attribute in the system catalog.
 * Attributes are used in Attribute-Based Encryption (ABE) policies.
 */
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

    /**
     * Returns the unique identifier for the attribute.
     * @return the attribute ID
     */
    public Integer getId() { return id; }

    /**
     * Sets the unique identifier for the attribute.
     * @param id the attribute ID to set
     */
    public void setId(Integer id) { this.id = id; }

    /**
     * Returns the name of the attribute.
     * @return the attribute name
     */
    public String getName() { return name; }

    /**
     * Sets the name of the attribute.
     * @param name the attribute name to set
     */
    public void setName(String name) { this.name = name; }

    /**
     * Returns the description of the attribute.
     * @return the attribute description
     */
    public String getDescription() { return description; }

    /**
     * Sets the description of the attribute.
     * @param description the attribute description to set
     */
    public void setDescription(String description) { this.description = description; }

    /**
     * Returns the timestamp when the attribute was created.
     * @return the creation timestamp
     */
    public LocalDateTime getCreatedAt() { return createdAt; }

    /**
     * Sets the timestamp when the attribute was created.
     * @param createdAt the creation timestamp to set
     */
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}
