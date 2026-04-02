package com.abe.clouddisk.dto;

/**
 * Data Transfer Object for assigning attributes to a user.
 */
public class AssignAttributesRequest {
    /**
     * The ID of the user to whom attributes will be assigned.
     */
    public Integer targetUserId;

    /**
     * A comma-separated string of attributes to assign.
     */
    public String attributes;
}
