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
