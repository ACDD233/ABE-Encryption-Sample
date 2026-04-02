package com.abe.clouddisk.entity;

import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;

/**
 * Entity representing the system-wide ABE parameters and master keys.
 * These keys are used to generate user keys and encrypt files.
 */
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

    /**
     * Returns the system key ID.
     * @return the ID
     */
    public Integer getId() {
        return id;
    }

    /**
     * Sets the system key ID.
     * @param id the ID to set
     */
    public void setId(Integer id) {
        this.id = id;
    }

    /**
     * Returns the ABE parameters.
     * @return the parameters string
     */
    public String getParams() {
        return params;
    }

    /**
     * Sets the ABE parameters.
     * @param params the parameters string to set
     */
    public void setParams(String params) {
        this.params = params;
    }

    /**
     * Returns the public parameter 'g'.
     * @return the 'g' bytes
     */
    public byte[] getG() {
        return g;
    }

    /**
     * Sets the public parameter 'g'.
     * @param g the 'g' bytes to set
     */
    public void setG(byte[] g) {
        this.g = g;
    }

    /**
     * Returns the public key component 'h'.
     * @return the 'h' bytes
     */
    public byte[] getPkH() {
        return pkH;
    }

    /**
     * Sets the public key component 'h'.
     * @param pkH the 'h' bytes to set
     */
    public void setPkH(byte[] pkH) {
        this.pkH = pkH;
    }

    /**
     * Returns the public key component 'eggAlpha'.
     * @return the 'eggAlpha' bytes
     */
    public byte[] getPkEggAlpha() {
        return pkEggAlpha;
    }

    /**
     * Sets the public key component 'eggAlpha'.
     * @param pkEggAlpha the 'eggAlpha' bytes to set
     */
    public void setPkEggAlpha(byte[] pkEggAlpha) {
        this.pkEggAlpha = pkEggAlpha;
    }

    /**
     * Returns the master secret key component 'beta'.
     * @return the 'beta' bytes
     */
    public byte[] getMskBeta() {
        return mskBeta;
    }

    /**
     * Sets the master secret key component 'beta'.
     * @param mskBeta the 'beta' bytes to set
     */
    public void setMskBeta(byte[] mskBeta) {
        this.mskBeta = mskBeta;
    }

    /**
     * Returns the master secret key component 'alpha'.
     * @return the 'alpha' bytes
     */
    public byte[] getMskAlpha() {
        return mskAlpha;
    }

    /**
     * Sets the master secret key component 'alpha'.
     * @param mskAlpha the 'alpha' bytes to set
     */
    public void setMskAlpha(byte[] mskAlpha) {
        this.mskAlpha = mskAlpha;
    }
}
