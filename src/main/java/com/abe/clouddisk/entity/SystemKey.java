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
import lombok.Getter;
import lombok.Setter;

/**
 * Entity representing the system-wide ABE parameters and master keys.
 * These keys are used to generate user keys and encrypt files.
 */
@Setter
@Getter
@TableName("system_keys")
public class SystemKey {

    /**
     * The unique identifier for the system key set.
     */
    @TableId
    private Integer id;

    /**
     * The ABE algorithm parameters in string format.
     */
    private String params;

    /**
     * The public parameter 'g' (generator).
     */
    private byte[] g;

    /**
     * The public key component 'h'.
     */
    private byte[] pkH;

    /**
     * The public key component 'eggAlpha'.
     */
    private byte[] pkEggAlpha;

    /**
     * The master secret key component 'beta'.
     */
    private byte[] mskBeta;

    /**
     * The master secret key component 'alpha'.
     */
    private byte[] mskAlpha;

}
