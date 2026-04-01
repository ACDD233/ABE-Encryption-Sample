package acdd.test.firsttest.entity;

import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;

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

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getParams() {
        return params;
    }

    public void setParams(String params) {
        this.params = params;
    }

    public byte[] getG() {
        return g;
    }

    public void setG(byte[] g) {
        this.g = g;
    }

    public byte[] getPkH() {
        return pkH;
    }

    public void setPkH(byte[] pkH) {
        this.pkH = pkH;
    }

    public byte[] getPkEggAlpha() {
        return pkEggAlpha;
    }

    public void setPkEggAlpha(byte[] pkEggAlpha) {
        this.pkEggAlpha = pkEggAlpha;
    }

    public byte[] getMskBeta() {
        return mskBeta;
    }

    public void setMskBeta(byte[] mskBeta) {
        this.mskBeta = mskBeta;
    }

    public byte[] getMskAlpha() {
        return mskAlpha;
    }

    public void setMskAlpha(byte[] mskAlpha) {
        this.mskAlpha = mskAlpha;
    }
}
