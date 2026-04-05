package com.abe.clouddisk.dto;

import lombok.Data;

/**
 * Data Transfer Object for updating a file's access policy.
 */
@Data
public class UpdatePolicyRequest {
    /**
     * The unique identifier of the file whose policy is being updated.
     */
    private Integer id;

    /**
     * A comma-separated string of attributes (tags) representing the new policy.
     */
    private String selectedTags;
}
