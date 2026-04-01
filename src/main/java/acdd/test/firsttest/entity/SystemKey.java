package acdd.test.firsttest.entity;

import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

@Data
@TableName("system_keys")
public class SystemKey {
    @TableId
    private Integer id;
    private String params;
    private byte[] g;
    private byte[] pkH;
    private byte[] pkEggAlpha;
    private byte[] mskBeta;
    private byte[] mskAlpha;
}
