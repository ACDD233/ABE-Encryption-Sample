/*
 * Copyright (C) 2026 ACDD233
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
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
