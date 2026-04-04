package com.abe.clouddisk.entity;

import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import com.baomidou.mybatisplus.annotation.IdType;
import lombok.Getter;
import lombok.Setter;

/**
 * Entity representing the Attribute-Based Encryption (ABE) components of a file.
 * This includes the encrypted session key and specific ABE ciphertext components.
 */
@Setter
@Getter
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

}
