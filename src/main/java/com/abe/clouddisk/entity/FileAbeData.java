package com.abe.clouddisk.entity;

import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import com.baomidou.mybatisplus.annotation.IdType;

/**
 * Entity representing the Attribute-Based Encryption (ABE) components of a file.
 * This includes the encrypted session key and specific ABE ciphertext components.
 */
@TableName("file_abe_data")
public class FileAbeData {
    /**
     * The ID of the file associated with this ABE data.
     */
    @TableId(type = IdType.INPUT)
    private Integer fileId;

    /**
     * The session key used for AES encryption, itself encrypted using ABE.
     */
    private byte[] encryptedSessionKey;

    /**
     * The 'C' component of the ABE ciphertext.
     */
    private byte[] ctC;

    /**
     * The 'C prime' component of the ABE ciphertext.
     */
    private byte[] ctCPrime;

    /**
     * Returns the file ID.
     * @return the file ID
     */
    public Integer getFileId() {
        return fileId;
    }

    /**
     * Sets the file ID.
     * @param fileId the file ID to set
     */
    public void setFileId(Integer fileId) {
        this.fileId = fileId;
    }

    /**
     * Returns the encrypted session key.
     * @return the encrypted session key bytes
     */
    public byte[] getEncryptedSessionKey() {
        return encryptedSessionKey;
    }

    /**
     * Sets the encrypted session key.
     * @param encryptedSessionKey the encrypted session key bytes to set
     */
    public void setEncryptedSessionKey(byte[] encryptedSessionKey) {
        this.encryptedSessionKey = encryptedSessionKey;
    }

    /**
     * Returns the 'C' component of the ABE ciphertext.
     * @return the ctC bytes
     */
    public byte[] getCtC() {
        return ctC;
    }

    /**
     * Sets the 'C' component of the ABE ciphertext.
     * @param ctC the ctC bytes to set
     */
    public void setCtC(byte[] ctC) {
        this.ctC = ctC;
    }

    /**
     * Returns the 'C prime' component of the ABE ciphertext.
     * @return the ctCPrime bytes
     */
    public byte[] getCtCPrime() {
        return ctCPrime;
    }

    /**
     * Sets the 'C prime' component of the ABE ciphertext.
     * @param ctCPrime the ctCPrime bytes to set
     */
    public void setCtCPrime(byte[] ctCPrime) {
        this.ctCPrime = ctCPrime;
    }
}
