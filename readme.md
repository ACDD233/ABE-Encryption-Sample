# ABE Cloud Storage

A secure cloud storage backend implementing **Attribute-Based Encryption (ABE)** and **Hybrid Encryption** (AES + ABE) using Spring Boot, MariaDB, and the JPBC library.

## Features

- **Ciphertext-Policy Attribute-Based Encryption (CP-ABE)**: Fine-grained access control where files are encrypted with a policy (e.g., `Dep:HR AND Role:Manager`).
- **Hybrid Encryption**: AES for high-speed file encryption, with the AES key protected by ABE.
- **Automated Deployment**: Fully containerized setup with health-checked dependencies.
- **Persistent Storage**: Named Docker volumes for database and encrypted file storage.

---

## Deployment Guide (Docker)

This project is designed to be "one-click" portable across Linux, macOS, and Windows.

### Prerequisites

- [Docker](https://www.docker.com/get-started) (Desktop or Engine)
- [Docker Compose](https://docs.docker.com/compose/install/) (V2 recommended)

### 1. Configuration (`.env`)

Create a `.env` file in the root directory. You can use the following template (ensure `JWT_SECRET` and passwords are changed for production):

```env
# MariaDB Configuration
DB_ROOT_PASSWORD={Your MariaDB Root Password}
DB_NAME=abe_cloud_disk
DB_USER=abe_user
DB_PASSWORD=h6Th5fA={Your MariaDB User Password}

# JWT Configuration (Optional)
JWT_SECRET=

# Internal Paths (Do not change unless modifying Dockerfile)
UPLOAD_DIR=/app/uploads
```

### 2. Start the Application

Run the following command to build the images and start the services in the background:

```bash
docker-compose up -d --build
```

### 3. Verification

- **API Status**: The application will be available at `http://localhost:8080`.
- **Database**: MariaDB is accessible internally by the app and externally at `localhost:3306`.
- **Initialization**: On the first run, the database schema and a default administrator account are automatically created.

Check logs to ensure everything is running:
```bash
docker-compose logs -f app
```

---

## Getting Started

### Default Administrator Credentials
Upon successful startup, the system initializes a default admin:
- **Email**: `admin@abe.com`
- **Password**: `admin123`

### Basic Workflow
1. **Login**: Use the `/abe/login` endpoint to receive a JWT token.
2. **Assign Attributes**: As an admin, assign attributes (e.g., `Department:Finance`) to users.
3. **Upload/Encrypt**: Upload a file with a specific access policy. The system generates an ABE-protected ciphertext.
4. **Download/Decrypt**: Users can download and decrypt files only if their attributes satisfy the file's policy.

---

## Technical Details

- **Automatic DB Init**: The `MariaDB.Dockerfile` bakes the `init.sql` into a custom image, resolving permission issues often found with volume-mounted scripts.
- **Security**: The application runs under a non-privileged user (`abeuser`) inside the container.
- **Portability**: Uses Docker **Named Volumes** (`uploads_data` and `mariadb_data`) to handle file permissions automatically across different operating systems.

## API Reference
Detailed documentation on endpoints, parameters, and logic:
- [English API Guide](API_GUIDE.md)
- [中文接口指南 (Chinese API Guide)](API_GUIDE_ZH.md)

## License
Apache License 2.0
