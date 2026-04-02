CREATE DATABASE IF NOT EXISTS abe_cloud_disk;
USE abe_cloud_disk;

-- 1. User table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    attributes TEXT, 
    role VARCHAR(20) DEFAULT 'USER', -- "USER" or "ADMIN"
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 2. ABE System Parameter Table
CREATE TABLE IF NOT EXISTS system_keys (
    id INT PRIMARY KEY DEFAULT 1,
    params TEXT NOT NULL,
    g BLOB NOT NULL,
    pk_h BLOB NOT NULL,
    pk_egg_alpha BLOB NOT NULL,
    msk_beta BLOB NOT NULL,
    msk_alpha BLOB NOT NULL,
    CHECK (id = 1)
) ENGINE=InnoDB;

-- 3. User ABE Private Key Table
CREATE TABLE IF NOT EXISTS user_keys (
    user_id INT PRIMARY KEY,
    sk_d BLOB NOT NULL,
    sk_dr BLOB NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 4. File metadata table
CREATE TABLE IF NOT EXISTS files (
    id INT AUTO_INCREMENT PRIMARY KEY,
    owner_id INT NOT NULL,
    filename VARCHAR(255) NOT NULL,
    file_path VARCHAR(500) NOT NULL,
    aes_iv VARBINARY(16) NOT NULL,
    policy TEXT NOT NULL,
    upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_dir TINYINT(1) DEFAULT 0,
    parent_id INT DEFAULT 0,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 5. File ABE Ciphertext Component Table
CREATE TABLE IF NOT EXISTS file_abe_data (
    file_id INT PRIMARY KEY,
    encrypted_session_key BLOB NOT NULL,
    ct_c BLOB NOT NULL,
    ct_c_prime BLOB NOT NULL,
    FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 6. Attribute Catalog: Stores available attributes for sharing/assignment
CREATE TABLE IF NOT EXISTS attributes_catalog (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE, -- e.g., "Dep:HR"
    description VARCHAR(255),          -- e.g., "Human Resources Department"
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;
