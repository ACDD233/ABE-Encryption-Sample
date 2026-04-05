package com.abe.clouddisk.controller;

import com.abe.clouddisk.common.util.JwtUtil;
import com.abe.clouddisk.dto.*;
import com.abe.clouddisk.entity.*;
import com.abe.clouddisk.mapper.UserKeyMapper;
import com.abe.clouddisk.service.ABEService;
import com.abe.clouddisk.service.FileService;
import com.abe.clouddisk.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Controller for handling Attribute-Based Encryption (ABE) related operations,
 * including user authentication, file encryption/decryption, and file system management.
 */
@Slf4j
@RestController
@RequestMapping("/abe")
@CrossOrigin(origins = "*")
public class ABEController {

    /**
     * Service for Attribute-Based Encryption operations.
     */
    @Autowired
    private ABEService abeService;

    /**
     * Service for user-related operations.
     */
    @Autowired
    private UserService userService;

    /**
     * Service for file system and metadata operations.
     */
    @Autowired
    private FileService fileService;

    /**
     * Mapper for accessing user cryptographic keys.
     */
    @Autowired
    private UserKeyMapper userKeyMapper;

    /**
     * Utility for JWT token operations.
     */
    @Autowired
    private JwtUtil jwtUtil;

    /**
     * Encoder for password hashing and verification.
     */
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    /**
     * Directory path where uploaded files are stored.
     */
    @Value("${file.upload-dir}")
    private String uploadDir;

    /**
     * Authenticates a user and returns a JWT token.
     *
     * @param req The login request containing email and password.
     * @return A ResponseEntity containing the authentication result or an error message.
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody LoginRequest req) {
        try {
            return ResponseEntity.ok(userService.login(req.getEmail(), req.getPassword()));
        } catch (Exception e) {
            Map<String, Object> res = new HashMap<>();
            res.put("error", e.getMessage());
            return ResponseEntity.status(401).body(res);
        }
    }

    /**
     * Registers a new user in the system.
     *
     * @param req The registration request containing username, email, and password.
     * @return A ResponseEntity containing the registration result or an error message.
     */
    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@RequestBody RegisterRequest req) {
        try {
            return ResponseEntity.ok(userService.register(req.getUsername(), req.getEmail(), req.getPassword()));
        } catch (Exception e) {
            Map<String, Object> res = new HashMap<>();
            res.put("error", e.getMessage());
            return ResponseEntity.status(500).body(res);
        }
    }

    /**
     * Uploads a file, encrypts it using ABE with a hybrid encryption scheme, and saves it to the server.
     *
     * @param file         The file to be encrypted and uploaded.
     * @param base64Key    The base64 encoded symmetric key used for initial encryption.
     * @param selectedTags Comma-separated tags selected for the ABE access policy.
     * @param parentIdStr  The ID of the parent directory where the file will be placed.
     * @param authHeader   The Authorization header containing the JWT token.
     * @return A ResponseEntity containing the file ID and status of the operation.
     */
    @PostMapping(value = "/encrypt-file", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Map<String, Object>> uploadAndEncrypt(
            @RequestPart("file") MultipartFile file,
            @RequestPart("key") String base64Key,
            @RequestPart(value = "selectedTags", required = false) String selectedTags,
            @RequestPart(value = "parentId", required = false) String parentIdStr,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {

        try {
            Integer ownerId = getUserIdFromHeader(authHeader);
            if (ownerId == null) return ResponseEntity.status(401).build();

            User user = userService.getById(ownerId);
            if (user == null) return ResponseEntity.status(404).build();

            Integer parentId = (parentIdStr != null && !parentIdStr.isEmpty()) ? Integer.parseInt(parentIdStr) : 0;

            String userAllAttrStr = user.getAttributes();
            Set<String> userOwnedSet = (userAllAttrStr == null || userAllAttrStr.isEmpty()) 
                    ? new HashSet<>() 
                    : Arrays.stream(userAllAttrStr.split(",")).map(String::trim).collect(Collectors.toSet());

            String identityTag = userOwnedSet.stream()
                    .filter(s -> s.startsWith("ID:"))
                    .findFirst()
                    .orElse("");

            Set<String> finalTagsSet = new LinkedHashSet<>();
            if (!identityTag.isEmpty()) {
                finalTagsSet.add(identityTag);
            }

            if (parentId != 0) {
                FileMetadata parent = (FileMetadata) fileService.getFileAndAbeData(parentId).get("file");
                if (parent != null && parent.getPolicy() != null) {
                    for (String pTag : parent.getPolicy().split(",")) {
                        String trimmed = pTag.trim();
                        if (!trimmed.isEmpty()) finalTagsSet.add(trimmed);
                    }
                }
            }

            if (selectedTags != null && !selectedTags.isEmpty()) {
                String[] requested = selectedTags.split(",");
                for (String reqTag : requested) {
                    String trimmedReq = reqTag.trim();
                    if (!trimmedReq.isEmpty() && !trimmedReq.startsWith("ID:")) {
                        if (userOwnedSet.contains(trimmedReq)) {
                            finalTagsSet.add(trimmedReq);
                        }
                    }
                }
            }

            String finalPolicyStr = String.join(",", finalTagsSet);
            String[] tagsArray = finalTagsSet.toArray(new String[0]);

            byte[] symmetricKey = Base64.getDecoder().decode(base64Key);
            ABEService.HybridCiphertext hc = abeService.encryptFileHybrid(file.getBytes(), symmetricKey, tagsArray);

            Files.createDirectories(Paths.get(uploadDir));

            String uniqueFileName = UUID.randomUUID() + ".enc";
            String fullPath = Paths.get(uploadDir, uniqueFileName).toString();
            try (FileOutputStream fos = new FileOutputStream(fullPath)) {
                fos.write(hc.aesEncryptedFile);
            }

            FileMetadata metadata = new FileMetadata();
            metadata.setOwnerId(ownerId);
            metadata.setFilename(file.getOriginalFilename());
            metadata.setFilePath(fullPath);
            metadata.setAesIv(hc.iv);
            metadata.setPolicy(finalPolicyStr);
            metadata.setIsDir(false);
            metadata.setParentId(parentId);
            metadata.setUploadTime(LocalDateTime.now());

            FileAbeData abeData = new FileAbeData();
            abeData.setEncryptedSessionKey(hc.abeEncryptedKey.encryptedSessionKey);
            abeData.setCtC(hc.abeEncryptedKey.getCBytes());
            abeData.setCtCPrime(hc.abeEncryptedKey.getCPrimeBytes());

            fileService.saveFileMetadata(metadata, abeData);

            Map<String, Object> res = new HashMap<>();
            res.put("fileId", metadata.getId());
            res.put("status", "success");
            res.put("policyApplied", finalPolicyStr);
            return ResponseEntity.ok(res);
        } catch (Exception e) {
            log.error("File upload and encryption failed for ownerId: {}", authHeader, e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * Lists files and directories within a specified parent directory for a given user.
     *
     * @param parentId   The ID of the parent directory.
     * @param authHeader The Authorization header containing the JWT token.
     * @return A ResponseEntity containing the list of items or an error message.
     */
    @GetMapping("/list")
    public ResponseEntity<Object> listFiles(
            @RequestParam(value = "parentId", defaultValue = "0") Integer parentId,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        Integer userId = getUserIdFromHeader(authHeader);
        if (userId == null) return ResponseEntity.status(401).build();
        
        try {
            return ResponseEntity.ok(fileService.listFiles(parentId, userId));
        } catch (Exception e) {
            Map<String, String> res = new HashMap<>();
            res.put("error", e.getMessage());
            // Return 403 for access denied, 404 for not found
            if (e.getMessage().contains("Access Denied")) {
                return ResponseEntity.status(403).body(res);
            }
            return ResponseEntity.status(404).body(res);
        }
    }

    /**
     * Creates a new directory.
     *
     * @param name       The name of the new directory.
     * @param parentId   The ID of the parent directory.
     * @param authHeader The Authorization header containing the JWT token.
     * @return A ResponseEntity indicating the status of the operation.
     */
    @PostMapping("/mkdir")
    public ResponseEntity<Map<String, String>> createDirectory(
            @RequestParam String name,
            @RequestParam(value = "parentId", defaultValue = "0") Integer parentId,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        Integer userId = getUserIdFromHeader(authHeader);
        if (userId == null) return ResponseEntity.status(401).build();

        User user = userService.getById(userId);
        String identityTag = Arrays.stream(user.getAttributes().split(","))
                .filter(s -> s.trim().startsWith("ID:"))
                .findFirst()
                .orElse("");

        fileService.createDirectory(name, parentId, identityTag, userId);
        Map<String, String> res = new HashMap<>();
        res.put("status", "success");
        res.put("policyApplied", identityTag);
        return ResponseEntity.ok(res);
    }

    /**
     * Deletes a file or directory.
     *
     * @param id         The ID of the item to delete.
     * @param authHeader The Authorization header containing the JWT token.
     * @return A ResponseEntity indicating the status of the operation.
     */
    @DeleteMapping("/delete/{id}")
    public ResponseEntity<Map<String, String>> deleteItem(
            @PathVariable Integer id,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        Integer userId = getUserIdFromHeader(authHeader);
        if (userId == null) return ResponseEntity.status(401).build();

        try {
            fileService.deleteItem(id, userId);
            Map<String, String> res = new HashMap<>();
            res.put("status", "success");
            return ResponseEntity.ok(res);
        } catch (Exception e) {
            Map<String, String> res = new HashMap<>();
            res.put("error", e.getMessage());
            return ResponseEntity.status(403).body(res);
        }
    }

    /**
     * Moves a file or directory to a new parent directory.
     *
     * @param id             The ID of the item to move.
     * @param targetParentId The ID of the target parent directory.
     * @param authHeader     The Authorization header containing the JWT token.
     * @return A ResponseEntity indicating the status of the operation.
     */
    @PostMapping("/move")
    public ResponseEntity<Map<String, String>> moveItem(
            @RequestParam Integer id,
            @RequestParam Integer targetParentId,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        Integer userId = getUserIdFromHeader(authHeader);
        if (userId == null) return ResponseEntity.status(401).build();
        fileService.moveItem(id, targetParentId, userId);
        Map<String, String> res = new HashMap<>();
        res.put("status", "success");
        return ResponseEntity.ok(res);
    }

    /**
     * Copies a file or directory to a new parent directory.
     *
     * @param id             The ID of the item to copy.
     * @param targetParentId The ID of the target parent directory.
     * @param authHeader     The Authorization header containing the JWT token.
     * @return A ResponseEntity indicating the status of the operation.
     */
    @PostMapping("/copy")
    public ResponseEntity<Map<String, String>> copyItem(
            @RequestParam Integer id,
            @RequestParam Integer targetParentId,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        Integer userId = getUserIdFromHeader(authHeader);
        if (userId == null) return ResponseEntity.status(401).build();
        fileService.copyItem(id, targetParentId, userId);
        Map<String, String> res = new HashMap<>();
        res.put("status", "success");
        return ResponseEntity.ok(res);
    }

    /**
     * Renames a file or directory.
     *
     * @param req        The rename request containing the item ID and new name.
     * @param authHeader The Authorization header containing the JWT token.
     * @return A ResponseEntity indicating the status of the operation.
     */
    @PostMapping("/rename")
    public ResponseEntity<Map<String, String>> renameItem(
            @RequestBody RenameRequest req,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        Integer userId = getUserIdFromHeader(authHeader);
        if (userId == null) return ResponseEntity.status(401).build();

        try {
            fileService.renameItem(req.getFileId(), req.getNewName(), userId);
            Map<String, String> res = new HashMap<>();
            res.put("status", "success");
            return ResponseEntity.ok(res);
        } catch (Exception e) {
            Map<String, String> res = new HashMap<>();
            res.put("error", e.getMessage());
            return ResponseEntity.status(403).body(res);
        }
    }

    /**
     * Shares a file by updating its ABE access policy.
     *
     * @param req        The share request containing the file ID and target policy.
     * @param authHeader The Authorization header containing the JWT token.
     * @return A ResponseEntity indicating the status of the operation or an error message.
     */
    @PostMapping("/share")
    public ResponseEntity<Map<String, String>> shareFile(
            @RequestBody ShareRequest req,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        Integer userId = getUserIdFromHeader(authHeader);
        if (userId == null) return ResponseEntity.status(401).build();

        try {
            // Validation: Only allow sharing of tags present in Catalog (or ID: personal tags)
            if (req.getTargetPolicy() != null && !req.getTargetPolicy().isEmpty()) {
                Set<String> validAttributes = userService.listAttributeCatalog().stream()
                        .map(AttributeCatalog::getName)
                        .collect(Collectors.toSet());

                String[] tags = req.getTargetPolicy().split(",");
                for (String t : tags) {
                    String trimmed = t.trim();
                    if (trimmed.isEmpty()) continue;
                    // Allow "ID:*" for direct individual sharing, but check others against Catalog
                    if (!trimmed.startsWith("ID:") && !validAttributes.contains(trimmed)) {
                        Map<String, String> res = new HashMap<>();
                        res.put("error", "The attribute '" + trimmed + "' is not a valid system attribute.");
                        return ResponseEntity.status(400).body(res);
                    }
                }
            }

            fileService.shareFile(req.getFileId(), req.getTargetPolicy(), userId);
            Map<String, String> res = new HashMap<>();
            res.put("status", "success");
            return ResponseEntity.ok(res);
        } catch (Exception e) {
            Map<String, String> res = new HashMap<>();
            res.put("error", e.getMessage());
            return ResponseEntity.status(500).body(res);
        }
    }

    /**
     * Updates the access policy of a file or directory.
     *
     * @param req        The update policy request containing the item ID and new tags.
     * @param authHeader The Authorization header containing the JWT token.
     * @return A ResponseEntity indicating the status of the operation or an error message.
     */
    @PostMapping("/update-policy")
    public ResponseEntity<Map<String, String>> updatePolicy(
            @RequestBody UpdatePolicyRequest req,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        Integer userId = getUserIdFromHeader(authHeader);
        if (userId == null) return ResponseEntity.status(401).build();

        try {
            User user = userService.getById(userId);
            Set<String> userOwnedSet = Arrays.stream(user.getAttributes().split(",")).map(String::trim).collect(Collectors.toSet());
            
            String validatedTags = "";
            if (req.getSelectedTags() != null && !req.getSelectedTags().isEmpty()) {
                String[] requested = req.getSelectedTags().split(",");
                List<String> validList = new ArrayList<>();
                for (String t : requested) {
                    String trimmed = t.trim();
                    if (trimmed.isEmpty()) continue;
                    if (!userOwnedSet.contains(trimmed)) {
                        Map<String, String> res = new HashMap<>();
                        res.put("error", "You do not possess the attribute: " + trimmed);
                        return ResponseEntity.status(403).body(res);
                    }
                    if (!trimmed.startsWith("ID:")) {
                        validList.add(trimmed);
                    }
                }
                validatedTags = String.join(",", validList);
            }

            fileService.updateItemPolicy(req.getId(), validatedTags, userId);
            Map<String, String> res = new HashMap<>();
            res.put("status", "success");
            res.put("policyApplied", validatedTags);
            return ResponseEntity.ok(res);
        } catch (Exception e) {
            Map<String, String> res = new HashMap<>();
            res.put("error", e.getMessage());
            return ResponseEntity.status(500).body(res);
        }
    }

    /**
     * Lists all available attributes from the system attribute catalog.
     *
     * @param authHeader The Authorization header containing the JWT token.
     * @return A ResponseEntity containing the list of attributes.
     */
    @GetMapping("/attributes")
    public ResponseEntity<List<AttributeCatalog>> listAttributes(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        Integer userId = getUserIdFromHeader(authHeader);
        if (userId == null) return ResponseEntity.status(401).build();
        return ResponseEntity.ok(userService.listAttributeCatalog());
    }

    /**
     * Returns the current user's ID and their assigned attributes.
     * Useful for refreshing user state when an admin assigns new tags.
     *
     * @param authHeader The Authorization header containing the JWT token.
     * @return A ResponseEntity containing the user ID and attributes.
     */
    @GetMapping("/my-attributes")
    public ResponseEntity<Map<String, Object>> getMyAttributes(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        Integer userId = getUserIdFromHeader(authHeader);
        if (userId == null) return ResponseEntity.status(401).build();

        User user = userService.getById(userId);
        if (user == null) return ResponseEntity.status(404).build();

        Map<String, Object> res = new HashMap<>();
        res.put("userId", user.getId());
        res.put("attributes", user.getAttributes());
        return ResponseEntity.ok(res);
    }

    /**
     * Admin only: Lists all users in the system.
     *
     * @param authHeader The Authorization header containing the JWT token.
     * @return A ResponseEntity containing the list of all users.
     */
    @GetMapping("/admin/users")
    public ResponseEntity<List<User>> listAllUsers(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        Integer adminId = getUserIdFromHeader(authHeader);
        if (adminId == null) return ResponseEntity.status(401).build();

        try {
            return ResponseEntity.ok(userService.listAllUsers(adminId));
        } catch (Exception e) {
            return ResponseEntity.status(403).build();
        }
    }

    /**
     * Admin only: Deletes a user by ID.
     *
     * @param id         The ID of the user to delete.
     * @param authHeader The Authorization header containing the JWT token.
     * @return A ResponseEntity indicating the status of the operation.
     */
    @DeleteMapping("/admin/users/{id}")
    public ResponseEntity<Map<String, String>> deleteUser(
            @PathVariable Integer id,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        Integer adminId = getUserIdFromHeader(authHeader);
        if (adminId == null) return ResponseEntity.status(401).build();

        try {
            userService.deleteUser(id, adminId);
            Map<String, String> res = new HashMap<>();
            res.put("status", "success");
            return ResponseEntity.ok(res);
        } catch (Exception e) {
            Map<String, String> res = new HashMap<>();
            res.put("error", e.getMessage());
            return ResponseEntity.status(403).body(res);
        }
    }

    /**
     * Admin only: Assigns attributes to a target user.
     *
     * @param req        The request containing the target user ID and attributes to assign.
     * @param authHeader The Authorization header containing the JWT token.
     * @return A ResponseEntity indicating the status of the operation.
     */
    @PostMapping("/admin/assign-attributes")
    public ResponseEntity<Map<String, String>> assignAttributes(
            @RequestBody AssignAttributesRequest req,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        Integer adminId = getUserIdFromHeader(authHeader);
        if (adminId == null) return ResponseEntity.status(401).build();

        try {
            userService.assignAttributes(req.getTargetUserId(), req.getAttributes(), adminId);
            Map<String, String> res = new HashMap<>();
            res.put("status", "success");
            res.put("newAttributes", req.getAttributes());
            return ResponseEntity.ok(res);
        } catch (Exception e) {
            Map<String, String> res = new HashMap<>();
            res.put("error", e.getMessage());
            return ResponseEntity.status(403).body(res);
        }
    }

    /**
     * Admin only: Adds a new attribute to the catalog.
     *
     * @param req        The attribute request containing name and description.
     * @param authHeader The Authorization header containing the JWT token.
     * @return A ResponseEntity indicating the status of the operation.
     */
    @PostMapping("/admin/attributes")
    public ResponseEntity<Map<String, String>> addAttribute(
            @RequestBody AttributeRequest req,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        Integer adminId = getUserIdFromHeader(authHeader);
        if (adminId == null) return ResponseEntity.status(401).build();

        try {
            userService.addAttributeToCatalog(req.getName(), req.getDescription(), adminId);
            Map<String, String> res = new HashMap<>();
            res.put("status", "success");
            return ResponseEntity.ok(res);
        } catch (Exception e) {
            Map<String, String> res = new HashMap<>();
            res.put("error", e.getMessage());
            return ResponseEntity.status(403).body(res);
        }
    }

    /**
     * Admin only: Deletes an attribute from the catalog by ID.
     *
     * @param id         The ID of the attribute to delete.
     * @param authHeader The Authorization header containing the JWT token.
     * @return A ResponseEntity indicating the status of the operation.
     */
    @DeleteMapping("/admin/attributes/{id}")
    public ResponseEntity<Map<String, String>> deleteAttribute(
            @PathVariable Integer id,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        Integer adminId = getUserIdFromHeader(authHeader);
        if (adminId == null) return ResponseEntity.status(401).build();

        try {
            userService.deleteAttributeFromCatalog(id, adminId);
            Map<String, String> res = new HashMap<>();
            res.put("status", "success");
            return ResponseEntity.ok(res);
        } catch (Exception e) {
            Map<String, String> res = new HashMap<>();
            res.put("error", e.getMessage());
            return ResponseEntity.status(403).body(res);
        }
    }

    /**
     * Extracts the user ID from the Authorization header.
     *
     * @param authHeader The Authorization header.
     * @return The user ID if the token is valid, null otherwise.
     */
    private Integer getUserIdFromHeader(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) return null;
        try {
            return Integer.parseInt(jwtUtil.getUserIdFromToken(authHeader.substring(7)));
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Downloads and decrypts a file based on the user's attributes and the file's ABE access policy.
     *
     * @param fileId         The ID of the file to download.
     * @param authHeader     The Authorization header (optional if other params provided).
     * @param userIdParam    The user ID (optional).
     * @param password       The user's password for verification (optional).
     * @param userAttributes Explicit attributes to use for decryption (optional).
     * @return A ResponseEntity containing the decrypted file resource.
     */
    @GetMapping("/download/{fileId}")
    public ResponseEntity<Resource> download(
            @PathVariable Integer fileId,
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestParam(value = "userId", required = false) Integer userIdParam,
            @RequestParam(value = "password", required = false) String password,
            @RequestParam(value = "userAttributes", required = false) String[] userAttributes) {

        try {
            Integer finalUserId = userIdParam;
            boolean isTokenAuth = false;
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                finalUserId = Integer.parseInt(jwtUtil.getUserIdFromToken(authHeader.substring(7)));
                isTokenAuth = true;
            }

            Map<String, Object> data = fileService.getFileAndAbeData(fileId);
            if (data == null || data.get("file") == null) return ResponseEntity.notFound().build();

            FileMetadata fileMeta = (FileMetadata) data.get("file");
            FileAbeData abeData = (FileAbeData) data.get("abeData");

            // Prevent downloading directories
            if (Boolean.TRUE.equals(fileMeta.getIsDir())) {
                return ResponseEntity.status(400).body(new ByteArrayResource("{\"error\": \"Cannot download a directory.\"}".getBytes()));
            }


            if (abeData == null) {
                log.error("Encrypted key data missing for fileId: {}", fileId);
                return ResponseEntity.status(500).build();
            }

            ABEService.ABECiphertext abeCt = new ABEService.ABECiphertext();
            abeCt.encryptedSessionKey = abeData.getEncryptedSessionKey();
            abeCt.tempCBytes = abeData.getCtC();
            abeCt.tempCPrimeBytes = abeData.getCtCPrime();

            if (fileMeta.getPolicy() != null) {
                for (String tag : fileMeta.getPolicy().split(",")) {
                    ABEService.CTComponent comp = new ABEService.CTComponent();
                    comp.attribute = tag.trim();
                    abeCt.components.add(comp);
                }
            }

            byte[] encryptedFile = Files.readAllBytes(Paths.get(fileMeta.getFilePath()));
            byte[] decryptedFile;

            if (finalUserId != null) {
                User user = userService.getById(finalUserId);
                if (!isTokenAuth && (password == null || !passwordEncoder.matches(password, user.getPasswordHash()))) {
                    return ResponseEntity.status(403).build();
                }

                UserKey uk = userKeyMapper.selectById(finalUserId);
                ABEService.SecretKeyContainer sk = new ABEService.SecretKeyContainer();
                sk.D = abeService.getElementFromBytes(uk.getSkD(), "G1");
                sk.D_r = abeService.getElementFromBytes(uk.getSkDr(), "G1");
                if (user.getAttributes() != null) {
                    for (String attr : user.getAttributes().split(",")) {
                        ABEService.SKComponent comp = new ABEService.SKComponent();
                        comp.attribute = attr.trim();
                        sk.components.add(comp);
                    }
                }

                byte[] recoveredKey = abeService.decryptSessionKey(sk, abeCt);
                if (recoveredKey == null) throw new RuntimeException("Attributes not match");
                decryptedFile = abeService.decryptAES(encryptedFile, recoveredKey, fileMeta.getAesIv());
            } else {
                ABEService.HybridCiphertext hc = new ABEService.HybridCiphertext();
                hc.aesEncryptedFile = encryptedFile;
                hc.abeEncryptedKey = abeCt;
                hc.iv = fileMeta.getAesIv();
                decryptedFile = abeService.decryptFileHybrid(hc, userAttributes);
            }

            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment()
                            .filename(fileMeta.getFilename(), java.nio.charset.StandardCharsets.UTF_8).build().toString())
                    .body(new ByteArrayResource(decryptedFile));
        } catch (Exception e) {
            log.error("File download or decryption failed for fileId: {}", fileId, e);
            return ResponseEntity.internalServerError().build();
        }
    }
}
