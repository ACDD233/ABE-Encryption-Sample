package acdd.test.firsttest.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;
import java.time.LocalDateTime;

@Data
@TableName("files")
public class FileMetadata {
    @TableId(type = IdType.AUTO)
    private Integer id;
    private Integer ownerId;
    private String filename;
    private String filePath;
    private byte[] aesIv;
    private String policy;
    private LocalDateTime uploadTime;
}
