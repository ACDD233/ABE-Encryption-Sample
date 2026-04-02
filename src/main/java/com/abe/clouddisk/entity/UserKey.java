package com.abe.clouddisk.entity;

import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import com.baomidou.mybatisplus.annotation.IdType;

/**
 * Entity representing the ABE secret key assigned to a user.
 */
@TableName("user_keys")
public class UserKey {
    /**
     * The ID of the user who owns this secret key.
     */
    @TableId(type = IdType.INPUT)
    private Integer userId;

    /**
     * The 'D' component of the user's ABE secret key.
     */
    private byte[] skD;

    /**
     * The 'Dr' component of the user's ABE secret key.
     */
    private byte[] skDr;

    /**
     * Returns the user ID.
     * @return the user ID
     */
    public Integer getUserId() {
        return userId;
    }

    /**
     * Sets the user ID.
     * @param userId the user ID to set
     */
    public void setUserId(Integer userId) {
        this.userId = userId;
    }

    /**
     * Returns the 'D' component of the secret key.
     * @return the skD bytes
     */
    public byte[] getSkD() {
        return skD;
    }

    /**
     * Sets the 'D' component of the secret key.
     * @param skD the skD bytes to set
     */
    public void setSkD(byte[] skD) {
        this.skD = skD;
    }

    /**
     * Returns the 'Dr' component of the secret key.
     * @return the skDr bytes
     */
    public byte[] getSkDr() {
        return skDr;
    }

    /**
     * Sets the 'Dr' component of the secret key.
     * @param skDr the skDr bytes to set
     */
    public void setSkDr(byte[] skDr) {
        this.skDr = skDr;
    }
}
