package acdd.test.firsttest.entity;

import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import com.baomidou.mybatisplus.annotation.IdType;

@TableName("file_abe_data")
public class FileAbeData {
    @TableId(type = IdType.INPUT)
    private Integer fileId;
    private byte[] encryptedSessionKey;
    private byte[] ctC;
    private byte[] ctCPrime;

    public Integer getFileId() {
        return fileId;
    }

    public void setFileId(Integer fileId) {
        this.fileId = fileId;
    }

    public byte[] getEncryptedSessionKey() {
        return encryptedSessionKey;
    }

    public void setEncryptedSessionKey(byte[] encryptedSessionKey) {
        this.encryptedSessionKey = encryptedSessionKey;
    }

    public byte[] getCtC() {
        return ctC;
    }

    public void setCtC(byte[] ctC) {
        this.ctC = ctC;
    }

    public byte[] getCtCPrime() {
        return ctCPrime;
    }

    public void setCtCPrime(byte[] ctCPrime) {
        this.ctCPrime = ctCPrime;
    }
}
