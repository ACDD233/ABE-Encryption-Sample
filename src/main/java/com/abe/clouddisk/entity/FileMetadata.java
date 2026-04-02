package com.abe.clouddisk.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import java.time.LocalDateTime;

/**
 * Entity representing metadata for a file stored in the system.
 */
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

    /**
     * Returns the file ID.
     * @return the file ID
     */
    public Integer getId() {
        return id;
    }

    /**
     * Sets the file ID.
     * @param id the file ID to set
     */
    public void setId(Integer id) {
        this.id = id;
    }

    /**
     * Returns the owner ID.
     * @return the owner ID
     */
    public Integer getOwnerId() {
        return ownerId;
    }

    /**
     * Sets the owner ID.
     * @param ownerId the owner ID to set
     */
    public void setOwnerId(Integer ownerId) {
        this.ownerId = ownerId;
    }

    /**
     * Returns the filename.
     * @return the filename
     */
    public String getFilename() {
        return filename;
    }

    /**
     * Sets the filename.
     * @param filename the filename to set
     */
    public void setFilename(String filename) {
        this.filename = filename;
    }

    /**
     * Returns the file path.
     * @return the file path
     */
    public String getFilePath() {
        return filePath;
    }

    /**
     * Sets the file path.
     * @param filePath the file path to set
     */
    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    /**
     * Returns the AES IV.
     * @return the AES IV bytes
     */
    public byte[] getAesIv() {
        return aesIv;
    }

    /**
     * Sets the AES IV.
     * @param aesIv the AES IV bytes to set
     */
    public void setAesIv(byte[] aesIv) {
        this.aesIv = aesIv;
    }

    /**
     * Returns the access policy.
     * @return the policy string
     */
    public String getPolicy() {
        return policy;
    }

    /**
     * Sets the access policy.
     * @param policy the policy string to set
     */
    public void setPolicy(String policy) {
        this.policy = policy;
    }

    /**
     * Returns the upload time.
     * @return the upload timestamp
     */
    public LocalDateTime getUploadTime() {
        return uploadTime;
    }

    /**
     * Sets the upload time.
     * @param uploadTime the upload timestamp to set
     */
    public void setUploadTime(LocalDateTime uploadTime) {
        this.uploadTime = uploadTime;
    }

    /**
     * Returns whether the entry is a directory.
     * @return true if it is a directory, false otherwise
     */
    public Boolean getIsDir() {
        return isDir;
    }

    /**
     * Sets whether the entry is a directory.
     * @param dir true if it is a directory, false otherwise
     */
    public void setIsDir(Boolean dir) {
        isDir = dir;
    }

    /**
     * Returns the parent directory ID.
     * @return the parent ID
     */
    public Integer getParentId() {
        return parentId;
    }

    /**
     * Sets the parent directory ID.
     * @param parentId the parent ID to set
     */
    public void setParentId(Integer parentId) {
        this.parentId = parentId;
    }
}
