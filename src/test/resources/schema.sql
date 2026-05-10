-- 1. User table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    attributes TEXT, 
    role VARCHAR(20) DEFAULT 'USER', -- "USER" or "ADMIN"
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. ABE System Parameter Table
CREATE TABLE system_keys (
    id INT DEFAULT 1 PRIMARY KEY,
    params TEXT NOT NULL,
    g BLOB NOT NULL,
    pk_h BLOB NOT NULL,
    pk_egg_alpha BLOB NOT NULL,
    msk_beta BLOB NOT NULL,
    msk_alpha BLOB NOT NULL,
    CHECK (id = 1)
);

-- 3. User ABE Private Key Table
CREATE TABLE user_keys (
    user_id INT PRIMARY KEY,
    sk_d BLOB NOT NULL,
    sk_dr BLOB NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 4. File metadata table
CREATE TABLE files (
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
);

-- 5. File ABE Ciphertext Component Table
CREATE TABLE file_abe_data (
    file_id INT PRIMARY KEY,
    encrypted_session_key BLOB NOT NULL,
    ct_c BLOB NOT NULL,
    ct_c_prime BLOB NOT NULL,
    FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
);

-- 6. Attribute Catalog: Stores available attributes for sharing/assignment
CREATE TABLE attributes_catalog (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE, -- e.g., "Dep:HR"
    description VARCHAR(255),          -- e.g., "Human Resources Department"
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
