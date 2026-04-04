package com.abe.clouddisk.entity;

import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import com.baomidou.mybatisplus.annotation.IdType;
import lombok.Getter;
import lombok.Setter;

/**
 * Entity representing the ABE secret key assigned to a user.
 */
@Setter
@Getter
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

}
