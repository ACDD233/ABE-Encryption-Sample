# ABE Cloud Storage

A secure cloud storage backend implementing **Attribute-Based Encryption (ABE)** and **Hybrid Encryption** (AES + ABE) using Spring Boot, MariaDB, and the JPBC library.

## Looking for the frontend? Check out [SecureShare-web](https://github.com/xiaomizhoujiayu-wq/SecureShare-web).

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
DB_PASSWORD={Your MariaDB User Password}

# JWT Configuration (Optional)
# In the testing environment, this field can be left empty.
# When the field is empty, a random 256-bit key will be generated each time the system restarts.
# This will cause users' login sessions to be invalidated after every system restart.
# In the production environment, it is recommended to set a fixed key here.
# Please make sure to use a tool such as openssl to generate the key-
# in order to ensure randomness and security.
# (openssl rand -base64 32)
# Expected key format: At least 256 bits (32 characters), entered here in Base64 format.

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

### 4. Run Tests (Optional)

You can verify the system's integrity by running the automated test suite:
```bash
./mvnw test
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

## Testing

The project includes a comprehensive suite of automated tests covering both API endpoints and core cryptographic logic.

### Prerequisites for Testing
- JDK 21+
- Maven (or use the provided `./mvnw`)

### Running All Tests
To run the entire test suite:
```bash
./mvnw test
```

### Test Categories

1.  **API Controller Tests (`ABEControllerTest`)**:
    - **Method**: Uses `MockMvc` and `@WebMvcTest`.
    - **Purpose**: Verifies REST endpoints, parameter binding, security authorization, and JSON response formats.
    - **Isolation**: All service layers and database mappers are mocked for high performance.

2.  **ABE Logic Integration Tests (`ABEServiceTest`)**:
    - **Method**: Uses `@SpringBootTest` with an **H2 In-Memory Database**.
    - **Purpose**: Verifies the actual mathematical correctness of ABE encryption/decryption and AES-GCM integration.
    - **Scenarios**: Includes tests for policy satisfaction (success) and policy mismatch (failure).

### Test Configuration
Tests use a separate profile defined in `src/test/resources/application-test.properties`, which automatically configures the H2 database and temporary upload paths.

---

## Technical Details

- **Automatic DB Init**: The `MariaDB.Dockerfile` bakes the `init.sql` into a custom image, resolving permission issues often found with volume-mounted scripts.
- **Security**: The application runs under a non-privileged user (`abeuser`) inside the container.
- **Portability**: Uses Docker **Named Volumes** (`uploads_data` and `mariadb_data`) to handle file permissions automatically across different operating systems.

## Core Dependencies

This project relies on the following key open-source library for its cryptographic operations:

- **[JPBC (Java Pairing-Based Cryptography)](https://github.com/emilianobonassi/jpbc)**: The foundational library for bilinear pairings required by Attribute-Based Encryption (ABE). 
  *Note: Since the original research website is no longer active, we use the reliable [emilianobonassi/jpbc](https://github.com/emilianobonassi/jpbc) implementation via JitPack.*

## API Reference
Detailed documentation on endpoints, parameters, and logic:
- [English API Guide](API_GUIDE.md)
- [中文接口指南 (Chinese API Guide)](API_GUIDE_ZH.md)

## License
Apache License 2.0
