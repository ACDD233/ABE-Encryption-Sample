package com.abe.clouddisk.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

/**
 * Entity representing metadata for a file stored in the system.
 */
@Setter
@Getter
@TableName("files")
public class FileMetadata {

    /**
     * The unique identifier for the file.
     */
    @TableId(type = IdType.AUTO)
    private Integer id;

    /**
     * The ID of the user who owns the file.
     */
    private Integer ownerId;

    /**
     * The original name of the file.
     */
    private String filename;

    /**
     * The storage path of the file on the server.
     */
    private String filePath;

    /**
     * The Initialization Vector (IV) used for AES encryption.
     */
    private byte[] aesIv;

    /**
     * The access policy associated with the file (ABE policy string).
     */
    private String policy;

    /**
     * The timestamp when the file was uploaded.
     */
    private LocalDateTime uploadTime;

    /**
     * Indicates whether this entry represents a directory.
     */
    private Boolean isDir;

    /**
     * The ID of the parent directory, if applicable.
     */
    private Integer parentId;

}
