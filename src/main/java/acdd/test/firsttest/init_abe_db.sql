CREATE DATABASE IF NOT EXISTS abe_cloud_disk;
USE abe_cloud_disk;

-- 1. 用户表：存储用户信息及其拥有的 ABE 属性
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    attributes TEXT, -- 存储用户的属性，例如 "LEAD_ENGINEER,PROJECT_PHOENIX"
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 2. ABE 系统参数表：存储全局公钥和主密钥 (BLOB 用于存储序列化后的数学元素)
CREATE TABLE IF NOT EXISTS system_keys (
    id INT PRIMARY KEY DEFAULT 1,
    params TEXT NOT NULL,        -- PairingParameters serialized
    g BLOB NOT NULL,             -- Element g (generator)
    pk_h BLOB NOT NULL,          -- Element h
    pk_egg_alpha BLOB NOT NULL,  -- Element egg_alpha
    msk_beta BLOB NOT NULL,      -- Element beta
    msk_alpha BLOB NOT NULL,     -- Element alpha
    CHECK (id = 1)               -- 确保只有一条记录
) ENGINE=InnoDB;

-- 3. 用户 ABE 私钥表：存储生成的个性化私钥组件
CREATE TABLE IF NOT EXISTS user_keys (
    user_id INT PRIMARY KEY,
    sk_d BLOB NOT NULL,          -- Element D
    sk_dr BLOB NOT NULL,         -- Element D_r
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 4. 文件元数据表：存储文件基本信息和前端传来的 AES IV
CREATE TABLE IF NOT EXISTS files (
    id INT AUTO_INCREMENT PRIMARY KEY,
    owner_id INT NOT NULL,
    filename VARCHAR(255) NOT NULL,
    file_path VARCHAR(500) NOT NULL, -- 加密文件在服务器上的物理路径
    aes_iv VARBINARY(16) NOT NULL,   -- 前端生成的 AES IV
    policy TEXT NOT NULL,            -- 访问策略描述，例如 "PROJECT_PHOENIX AND LEAD_ENGINEER"
    upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 5. 文件 ABE 密文组件表：存储被 ABE 保护的 AES 密钥
CREATE TABLE IF NOT EXISTS file_abe_data (
    file_id INT PRIMARY KEY,
    encrypted_session_key BLOB NOT NULL, -- 被 ABE 掩码后的 AES 密钥字节
    ct_c BLOB NOT NULL,                  -- Element C
    ct_c_prime BLOB NOT NULL,            -- Element C_prime
    FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
) ENGINE=InnoDB;
