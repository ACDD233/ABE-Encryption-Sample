package com.abe.clouddisk.dto;

/**
 * Data Transfer Object for creating or updating attributes in the system catalog.
 * Used primarily by administrators to define new ABE tags.
 */
public class AttributeRequest {
    
    /**
     * The unique name of the attribute (e.g., "Dep:HR").
     */
    public String name;
    
    /**
     * A brief description of what this attribute represents.
     */
    public String description;
}
