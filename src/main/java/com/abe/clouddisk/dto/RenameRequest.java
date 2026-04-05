package com.abe.clouddisk.dto;

import lombok.Data;

/**
 * Data Transfer Object for file or directory rename requests.
 */
@Data
public class RenameRequest {
    /**
     * The unique identifier of the file or directory to be renamed.
     */
    private Integer fileId;

    /**
     * The new name for the file or directory.
     */
    private String newName;
}
