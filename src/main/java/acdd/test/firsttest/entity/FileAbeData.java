package acdd.test.firsttest.entity;

import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import com.baomidou.mybatisplus.annotation.IdType;
import lombok.Data;

@Data
@TableName("file_abe_data")
public class FileAbeData {
    @TableId(type = IdType.INPUT)
    private Integer fileId;
    private byte[] encryptedSessionKey;
    private byte[] ctC;
    private byte[] ctCPrime;
}
