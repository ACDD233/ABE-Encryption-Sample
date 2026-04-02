package com.abe.clouddisk.dto;

/**
 * Data Transfer Object for file sharing requests.
 */
public class ShareRequest {
    /**
     * The unique identifier of the file to be shared.
     */
    public Integer fileId;

    /**
     * The ABE access policy defining who can access the shared file.
     */
    public String targetPolicy;
}
