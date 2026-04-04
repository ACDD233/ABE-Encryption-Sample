# ABE 加密网盘项目 - 接口文档 (API Documentation)

本指南详细介绍了所有可用的 API 端点、预期输入以及示例输出。

## 基础 URL
`http://localhost:8080/abe`

## 身份验证 (Authentication)
大多数接口都需要 **JWT Bearer Token**。
请在请求头（Header）中包含以下信息：
`Authorization: Bearer <您的_token>`

---

### 1. 用户与身份验证

#### **登录 (Login)**
进行身份验证并获取 JWT Token。
- **端点**: `POST /login`
- **请求体 (JSON)**:
  ```json
  {
    "email": "admin@abe.com",
    "password": "admin123"
  }
  ```
- **响应**:
  ```json
  {
    "token": "eyJhbGci...",
    "username": "SuperAdmin",
    "userId": 1,
    "role": "ADMIN",
    "attributes": "ID:USER-uuid,Dep:Finance"
  }
  ```

#### **注册 (Register)**
创建新用户账号。
- **端点**: `POST /register`
- **请求体 (JSON)**:
  ```json
  {
    "username": "johndoe",
    "email": "john@example.com",
    "password": "password123"
  }
  ```

#### **获取我的属性 (Get My Attributes)**
检索当前用户的 ID 和已分配的 ABE 属性。
- **端点**: `GET /my-attributes`
- **响应**:
  ```json
  {
    "userId": 2,
    "attributes": "ID:USER-uuid,Dep:Engineering"
  }
  ```

---

### 2. 文件与目录管理

*注意：关于层级文件系统、ParentId 逻辑以及 ABE 策略继承的详细解释，请参阅 [第五节：文件系统与策略逻辑](#5-文件系统与策略逻辑-关键概念)。*

#### **获取文件/目录列表 (List)**
列出特定父目录下的所有项。
- **端点**: `GET /list`
- **查询参数**: `parentId` (整数, 默认为 0，即根目录)
- **响应**: 包含文件/目录对象的列表，包括 `id`, `filename`, `policy`, `isDir` 等字段。

#### **上传并加密文件 (Upload & Encrypt)**
上传文件并应用 ABE + AES 混合加密。
- **端点**: `POST /encrypt-file`
- **类型**: `multipart/form-data`
- **参数**:
  - `file`: (二进制) 待上传的文件。
  - `key`: (Base64 字符串) 待保护的 32 字节 AES 对称密钥。
  - `selectedTags`: (字符串, 可选) 逗号分隔的属性列表，用于定义 ABE 策略。
  - `parentId`: (整数, 可选) 目标目录 ID。
- **响应**:
  ```json
  {
    "fileId": 12,
    "status": "success",
    "policyApplied": "ID:USER-uuid,Dep:Finance"
  }
  ```

#### **下载并解密文件 (Download & Decrypt)**
下载文件并使用用户的 ABE 私钥进行解密。
- **端点**: `GET /download/{fileId}`
- **身份验证**: 支持 Header 中的 Token 或查询参数 (`userId`, `password`)。
- **行为**: 服务器会自动尝试使用用户的属性恢复 AES 密钥。如果属性不满足策略，请求将返回 403/500 错误。
- **输出**: 二进制文件流。

#### **创建目录 (Create Directory)**
- **端点**: `POST /mkdir`
- **查询参数**: `name` (目录名), `parentId` (父目录 ID)

#### **删除 / 移动 / 复制 (File Operations)**
- **删除**: `DELETE /delete/{id}`
- **移动**: `POST /move?id=1&targetParentId=2`
- **复制**: `POST /copy?id=1&targetParentId=2`

---

### 3. 分享与策略更新

#### **分享文件 (Share)**
更新文件的访问策略以包含新的属性标签。
- **端点**: `POST /share`
- **请求体 (JSON)**:
  ```json
  {
    "fileId": 12,
    "targetPolicy": "Dep:HR,Role:Manager"
  }
  ```

#### **更新策略 (Update Policy)**
直接覆盖文件或目录的当前 ABE 策略。
- **端点**: `POST /update-policy`
- **请求体 (JSON)**:
  ```json
  {
    "id": 12,
    "selectedTags": "Dep:Engineering,Role:Developer"
  }
  ```
- **验证规则**:
  - 您必须是该文件/目录的 **所有者 (Owner)**。
  - **自持属性规则**: 您只能应用 **您自己当前持有** 的标签。例如，如果您不在“财务部”，您不能通过此接口将文件的策略设置为 "Dep:Finance"。
- **行为**: 与 `/share` 不同，此操作会 **替换** 整个现有策略（除了您自己的 `ID:` 标签，该标签始终会被保留，以确保所有者始终能解密自己的文件）。

---

### 4. 管理员操作 (需 ADMIN 角色)

这些端点仅限具有 `ADMIN` 角色的用户访问。

#### **列出所有用户 (List Users)**
- **端点**: `GET /admin/users`
- **响应**: `User` 对象列表。

#### **删除用户 (Delete User)**
永久删除用户及其关联的文件和密钥。
- **端点**: `DELETE /admin/users/{id}`
- **安全限制**: 
  - 管理员不能删除自己的账号。
  - 管理员账号不能被删除。
- **行为**: 该操作会级联删除用户的所有文件记录和 ABE 私钥。

#### **分配/更新用户 ABE 属性 (权限管理)**
更新用户的 ABE 权限集并重新生成其私钥。
- **端点**: `POST /admin/assign-attributes`
- **请求体 (JSON)**:
  ```json
  {
    "targetUserId": 2,
    "attributes": "Dep:HR,Role:Manager"
  }
  ```
- **关键行为**: 
  - **覆盖写入**: 此操作会 **替换** 用户除固定 `ID:uuid` 标签外的所有现有属性。
  - **密钥重生成**: 系统会 **立即为用户生成新的 ABE 私钥**。用户下次尝试解密文件时，服务器将使用这些新密钥。
  - **权限撤销**: 在此处移除某个标签，实际上是撤销了用户解密任何需要该标签的文件（无论是新文件还是旧文件）的能力。

#### **添加属性到目录 (Add Attribute)**
在系统中注册一个新的有效属性标签。
- **端点**: `POST /admin/attributes`
- **请求体 (JSON)**: `{ "name": "...", "description": "..." }`

#### **删除属性 (Delete Attribute)**
从有效目录中移除某个属性标签。
- **端点**: `DELETE /admin/attributes/{id}`

#### **获取属性目录 (Attribute Catalog)**
- **端点**: `GET /attributes` (所有登录用户均可访问，用于查看分享时可用的标签)。

---

### 5. 文件系统与策略逻辑 (关键概念)

本项目使用层级化、策略继承的文件系统。理解 `ParentId` 与 ABE 策略的交互是集成的关键。

#### **ParentId 的作用**
- `ParentId = 0`: 代表用户云盘的根目录。
- `ParentId = {ID}`: 将文件/目录链接到其父文件夹，形成“链式文件夹”结构。
- **访问检查**: 要列出或访问子目录，用户必须同时满足父目录 **和** 该子项本身的 ABE 策略。

#### **策略继承与合并 (Policy Inheritance)**
在文件夹内创建项时：
- **规则**: `项策略 = 父目录策略 + 所有者身份标签 (ID:) + 自定义标签`。
- 这确保了权限是向下流动的。如果一个文件夹被限制为 "Dep:Finance"，上传到其中的所有文件都会自动继承该限制。

#### **移动操作 (`/move`)**
移动项不仅仅是更改 `ParentId`：
1. **逻辑移动**: 更改目标的 `ParentId`。
2. **递归重加密**: 由于目标父目录可能有不同的 ABE 策略，系统会 **自动为该项及其所有子项重新加密** ABE 组件（即 Session Key 部分）。
3. **高效性**: 实际的加密文件内容（AES 部分）**不会**被重新处理，仅更新微小的 ABE 元数据。

#### **复制操作 (`/copy`)**
复制采用“智能复制”逻辑：
1. **元数据复制**: 在数据库中创建新记录。
2. **策略适配**: 根据 **目标父目录** 的策略重新计算新副本的 ABE 策略。
3. **延迟文件复制**: 副本最初指向磁盘上同一个物理 `.enc` 文件以节省空间，但其访问权限由完全独立的 ABE 密文控制。

#### **分享 (`/share`)**
分享文件夹是 **递归的**。如果您将文件夹分享给“用户：张三”，系统会为该文件夹内的每一个文件递归生成新的 ABE 元数据，确保张三可以访问整个目录树。

---

### 6. 常见错误码
- `401 Unauthorized`: 缺少或无效的 JWT Token。
- `403 Forbidden`: 用户不具备访问该资源所需的属性，或不具备管理员权限。
- `404 Not Found`: 文件、目录或用户不存在。
- `500 Internal Server Error`: 通常表示 ABE 解密失败（属性不匹配）或文件系统错误。
