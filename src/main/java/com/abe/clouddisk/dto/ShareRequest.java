package com.abe.clouddisk.dto;

import lombok.Data;

/**
 * Data Transfer Object for file sharing requests.
 */
@Data
public class ShareRequest {
    /**
     * The unique identifier of the file to be shared.
     */
    private Integer fileId;

    /**
     * The ABE access policy defining who can access the shared file.
     */
    private String targetPolicy;
}
