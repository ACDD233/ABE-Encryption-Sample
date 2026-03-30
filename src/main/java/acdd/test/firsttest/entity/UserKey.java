package acdd.test.firsttest.entity;

import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import com.baomidou.mybatisplus.annotation.IdType;
import lombok.Data;

@Data
@TableName("user_keys")
public class UserKey {
    @TableId(type = IdType.INPUT)
    private Integer userId;
    private byte[] skD;
    private byte[] skDr;
}
