package com.abe.clouddisk.dto;

import lombok.Data;

/**
 * Data Transfer Object for assigning attributes to a user.
 */
@Data
public class AssignAttributesRequest {
    /**
     * The ID of the user to whom attributes will be assigned.
     */
    private Integer targetUserId;

    /**
     * A comma-separated string of attributes to assign.
     */
    private String attributes;
}
