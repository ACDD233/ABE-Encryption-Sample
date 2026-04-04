# ABE Encryption Sample - API Documentation

This guide provides detailed information on all available API endpoints, their expected inputs, and sample outputs.

## Base URL
`http://localhost:8080/abe`

## Authentication
Most endpoints require a **JWT Bearer Token**. 
Include the following header in your requests:
`Authorization: Bearer <your_token>`

---

### 1. User & Authentication

#### **Login**
Authenticate and retrieve a JWT token.
- **Endpoint**: `POST /login`
- **Body (JSON)**:
  ```json
  {
    "email": "admin@abe.com",
    "password": "admin123"
  }
  ```
- **Response**:
  ```json
  {
    "token": "eyJhbGci...",
    "username": "SuperAdmin",
    "userId": 1,
    "role": "ADMIN",
    "attributes": "ID:USER-uuid,Dep:Finance"
  }
  ```

#### **Register**
Create a new user account.
- **Endpoint**: `POST /register`
- **Body (JSON)**:
  ```json
  {
    "username": "johndoe",
    "email": "john@example.com",
    "password": "password123"
  }
  ```

#### **Get My Attributes**
Retrieve the current user's ID and assigned ABE attributes.
- **Endpoint**: `GET /my-attributes`
- **Response**:
  ```json
  {
    "userId": 2,
    "attributes": "ID:USER-uuid,Dep:Engineering"
  }
  ```

---

### 2. File & Directory Management

*Note: For a detailed explanation of the hierarchical file system, ParentId logic, and policy inheritance, please refer to [Section 5: File System & Policy Logic](#5-file-system--policy-logic-crucial).*

#### **List Files/Directories**
List items in a specific parent directory.
- **Endpoint**: `GET /list`
- **Query Params**: `parentId` (Integer, default: 0)
- **Response**: A list of file/directory objects including `id`, `filename`, `policy`, `isDir`, etc.

#### **Upload & Encrypt File**
Upload a file and apply ABE + AES hybrid encryption.
- **Endpoint**: `POST /encrypt-file`
- **Type**: `multipart/form-data`
- **Parameters**:
  - `file`: (Binary) The file to upload.
  - `key`: (Base64 String) The 32-byte AES symmetric key to protect.
  - `selectedTags`: (String, Optional) Comma-separated list of attributes for the policy.
  - `parentId`: (Integer, Optional) Target directory ID.
- **Response**:
  ```json
  {
    "fileId": 12,
    "status": "success",
    "policyApplied": "ID:USER-uuid,Dep:Finance"
  }
  ```

#### **Download & Decrypt File**
Download a file and decrypt it using the user's ABE keys.
- **Endpoint**: `GET /download/{fileId}`
- **Authentication**: Token in Header OR query parameters (`userId`, `password`).
- **Behavior**: The server automatically attempts to recover the AES key using the user's attributes. If they do not satisfy the policy, the request returns a 403/500 error.
- **Output**: Binary file stream.

#### **Create Directory**
- **Endpoint**: `POST /mkdir`
- **Query Params**: `name`, `parentId`

#### **Delete / Move / Copy**
- **Delete**: `DELETE /delete/{id}`
- **Move**: `POST /move?id=1&targetParentId=2`
- **Copy**: `POST /copy?id=1&targetParentId=2`

---

### 3. Sharing & Policy Updates

#### **Share File**
Update a file's access policy to include new attributes.
- **Endpoint**: `POST /share`
- **Body (JSON)**:
  ```json
  {
    "fileId": 12,
    "targetPolicy": "Dep:HR,Role:Manager"
  }
  ```

#### **Update Policy**
Overwrite the current ABE policy of a file or directory.
- **Endpoint**: `POST /update-policy`
- **Body (JSON)**:
  ```json
  {
    "id": 12,
    "selectedTags": "Dep:Engineering,Role:Developer"
  }
  ```
- **Validation Rules**:
  - You must be the **owner** of the file/directory.
  - **Self-Possession Rule**: You can only apply tags that **you currently possess**. For example, if you are not in the "Finance" department, you cannot set a file's policy to "Dep:Finance" using this endpoint.
- **Behavior**: Unlike `/share`, this **replaces** the entire existing policy (except for your own `ID:` tag which is always preserved to ensure the owner can always decrypt their own files).

---

### 4. Admin Operations (Require Admin Role)

These endpoints are only accessible by users with the `ADMIN` role.

#### **List All Users**
Retrieve a list of all registered users.
- **Endpoint**: `GET /admin/users`
- **Response**: `List<User>`

#### **Delete User**
Permanently remove a user and their associated files/keys.
- **Endpoint**: `DELETE /admin/users/{id}`
- **Security**: 
  - Admins cannot delete their own account.
  - Administrative accounts cannot be deleted.
- **Behavior**: This also triggers the deletion of the user's files and ABE keys.

#### **Assign/Update User ABE Attributes (Privilege Management)**
Update a user's set of ABE privileges and regenerate their private keys.
- **Endpoint**: `POST /admin/assign-attributes`
- **Body (JSON)**:
  ```json
  {
    "targetUserId": 2,
    "attributes": "Dep:HR,Role:Manager"
  }
  ```
- **Crucial Behavior**: 
  - **Overwrite**: This **replaces** all existing attributes (except for the fixed `ID:uuid` tag).
  - **Key Regeneration**: The system **immediately generates new ABE private keys** for the user. The next time the user tries to decrypt a file, the server will use these new keys.
  - **Revocation**: Removing an attribute here effectively revokes the user's ability to decrypt any future (or existing) files that require that specific attribute.

#### **Add Attribute to Catalog**
Register a new valid attribute in the system.
- **Endpoint**: `POST /admin/attributes`
- **Body (JSON)**:
  ```json
  {
    "name": "Dep:Engineering",
    "description": "Engineering Department"
  }
  ```

#### **Delete Attribute from Catalog**
Remove an attribute from the valid catalog.
- **Endpoint**: `DELETE /admin/attributes/{id}`
- **Note**: This does not retroactively remove the attribute from users who already possess it, but it prevents new assignments or sharing using this attribute.

#### **List Attribute Catalog**
- **Endpoint**: `GET /attributes` (Accessible by all logged-in users to see available tags for sharing).

### 5. File System & Policy Logic (Crucial)

This project uses a hierarchical, policy-inherited file system. Understanding how `ParentId` and ABE policies interact is key for successful integration.

#### **The Role of ParentId**
- `ParentId = 0`: Represents the root of the user's cloud drive.
- `ParentId = {ID}`: Links a file or directory to its parent folder, forming a "Chained Folder" structure.
- **Access Check**: To list or access a subdirectory, the user must satisfy the ABE policy of **both** the parent directory and the specific item.

#### **Policy Inheritance & Merging**
When an item is created inside a folder:
- **Rule**: `Item Policy = Parent Policy + Owner's Identity Tag + Custom Tags`.
- This ensures that access rights flow downward. If a folder is restricted to "Dep:Finance", all files uploaded to it will automatically inherit that restriction.

#### **Move Operation (`/move`)**
Moving an item is more than just changing its `ParentId`.
1. **Logical Move**: Changes the `ParentId` to the new target.
2. **Recursive Re-Encryption**: Because the target parent may have a different ABE policy, the system **automatically re-encrypts** the ABE component (the session key) for the moved item and all its children.
3. **Efficiency**: The actual encrypted file content (AES part) is **never re-uploaded or re-processed**, only the small ABE metadata is updated.

#### **Copy Operation (`/copy`)**
Copying implements a "Smart Copy" logic:
1. **Metadata Duplication**: Creates a new record in the database.
2. **Policy Adaptation**: The new copy's policy is recalculated based on the **target** parent's policy.
3. **Lazy File Copy**: The copy initially points to the same physical `.enc` file on disk to save space, but its access is controlled by a completely unique ABE ciphertext.

#### **Sharing (`/share`)**
Sharing a folder is **recursive**. If you share a folder with "User:Alice", the system recursively generates new ABE metadata for every file inside that folder so Alice can access the entire tree.

---

### 6. Common Error Codes
- `401 Unauthorized`: Missing or invalid JWT token.
- `403 Forbidden`: User does not have sufficient attributes to access the resource or is not an admin.
- `404 Not Found`: File, directory, or user does not exist.
- `500 Internal Server Error`: Usually indicates an ABE decryption failure (attribute mismatch) or file system error.
