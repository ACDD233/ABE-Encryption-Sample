package com.abe.clouddisk.dto;

import lombok.Data;

/**
 * Data Transfer Object for creating or updating attributes in the system catalog.
 * Used primarily by administrators to define new ABE tags.
 */
@Data
public class AttributeRequest {
    
    /**
     * The unique name of the attribute (e.g., "Dep:HR").
     */
    private String name;
    
    /**
     * A brief description of what this attribute represents.
     */
    private String description;
}
