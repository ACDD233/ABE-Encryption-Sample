package acdd.test.firsttest.entity;

import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import com.baomidou.mybatisplus.annotation.IdType;

@TableName("user_keys")
public class UserKey {
    @TableId(type = IdType.INPUT)
    private Integer userId;
    private byte[] skD;
    private byte[] skDr;

    public Integer getUserId() {
        return userId;
    }

    public void setUserId(Integer userId) {
        this.userId = userId;
    }

    public byte[] getSkD() {
        return skD;
    }

    public void setSkD(byte[] skD) {
        this.skD = skD;
    }

    public byte[] getSkDr() {
        return skDr;
    }

    public void setSkDr(byte[] skDr) {
        this.skDr = skDr;
    }
}
