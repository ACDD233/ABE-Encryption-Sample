package com.abe.clouddisk.dto;

/**
 * Data Transfer Object for updating a file's access policy.
 */
public class UpdatePolicyRequest {
    /**
     * The unique identifier of the file whose policy is being updated.
     */
    public Integer id;

    /**
     * A comma-separated string of attributes (tags) representing the new policy.
     */
    public String selectedTags;
}
