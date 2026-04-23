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

    @Autowired
    private ABEService abeService;

    @Autowired
    private UserService userService;

    @Autowired
    private FileService fileService;

    @Autowired
    private UserKeyMapper userKeyMapper;

    @Autowired
    private JwtUtil jwtUtil;

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Value("${file.upload-dir}")
    private String uploadDir;

    /**
     * Global Exception Handler to capture business and system exceptions.
     * Maps exception messages to appropriate HTTP status codes and returns a JSON error response.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleException(Exception e) {
        String message = e.getMessage() == null ? "Internal Server Error" : e.getMessage();
        Map<String, Object> res = new HashMap<>();
        res.put("error", message);

        if (e instanceof IllegalArgumentException || message.contains("already exists")) {
            return ResponseEntity.badRequest().body(res);
        } else if (message.toLowerCase().contains("not found")) {
            return ResponseEntity.status(404).body(res);
        } else if (message.toLowerCase().contains("unauthorized") || message.toLowerCase().contains("login failed")) {
            return ResponseEntity.status(401).body(res);
        } else if (message.toLowerCase().contains("permission denied") || message.toLowerCase().contains("access denied") || message.toLowerCase().contains("forbidden")) {
            return ResponseEntity.status(403).body(res);
        }

        log.error("Unhandled Exception: ", e);
        return ResponseEntity.status(500).body(res);
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody LoginRequest req) {
        return ResponseEntity.ok(userService.login(req.getEmail(), req.getPassword()));
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@RequestBody RegisterRequest req) {
        return ResponseEntity.ok(userService.register(req.getUsername(), req.getEmail(), req.getPassword()));
    }

    @PostMapping(value = "/encrypt-file", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Map<String, Object>> uploadAndEncrypt(
            @RequestPart("file") MultipartFile file,
            @RequestPart("key") String base64Key,
            @RequestPart(value = "selectedTags", required = false) String selectedTags,
            @RequestPart(value = "parentId", required = false) String parentIdStr,
            @RequestHeader(value = "Authorization", required = false) String authHeader) throws Exception {

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
        if (!identityTag.isEmpty()) finalTagsSet.add(identityTag);

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
    }

    @GetMapping("/list")
    public ResponseEntity<Object> listFiles(
            @RequestParam(value = "parentId", defaultValue = "0") Integer parentId,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        Integer userId = getUserIdFromHeader(authHeader);
        if (userId == null) return ResponseEntity.status(401).build();
        return ResponseEntity.ok(fileService.listFiles(parentId, userId));
    }

    @PostMapping("/mkdir")
    public ResponseEntity<Map<String, Object>> createDirectory(
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

        Integer id = fileService.createDirectory(name, parentId, identityTag, userId);
        Map<String, Object> res = new HashMap<>();
        res.put("status", "success");
        res.put("id", id);
        res.put("policyApplied", identityTag);
        return ResponseEntity.ok(res);
    }

    @DeleteMapping("/delete/{id}")
    public ResponseEntity<Map<String, String>> deleteItem(
            @PathVariable Integer id,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        Integer userId = getUserIdFromHeader(authHeader);
        if (userId == null) return ResponseEntity.status(401).build();

        fileService.deleteItem(id, userId);
        Map<String, String> res = new HashMap<>();
        res.put("status", "success");
        return ResponseEntity.ok(res);
    }

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

    @PostMapping("/rename")
    public ResponseEntity<Map<String, String>> renameItem(
            @RequestBody RenameRequest req,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        Integer userId = getUserIdFromHeader(authHeader);
        if (userId == null) return ResponseEntity.status(401).build();

        fileService.renameItem(req.getFileId(), req.getNewName(), userId);
        Map<String, String> res = new HashMap<>();
        res.put("status", "success");
        return ResponseEntity.ok(res);
    }

    @PostMapping("/share")
    public ResponseEntity<Map<String, String>> shareFile(
            @RequestBody ShareRequest req,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        Integer userId = getUserIdFromHeader(authHeader);
        if (userId == null) return ResponseEntity.status(401).build();

        if (req.getTargetPolicy() != null && !req.getTargetPolicy().isEmpty()) {
            Set<String> validAttributes = userService.listAttributeCatalog().stream()
                    .map(AttributeCatalog::getName)
                    .collect(Collectors.toSet());

            String[] tags = req.getTargetPolicy().split(",");
            for (String t : tags) {
                String trimmed = t.trim();
                if (trimmed.isEmpty()) continue;
                if (!trimmed.startsWith("ID:") && !validAttributes.contains(trimmed)) {
                    throw new IllegalArgumentException("The attribute '" + trimmed + "' is not a valid system attribute.");
                }
            }
        }

        fileService.shareFile(req.getFileId(), req.getTargetPolicy(), userId);
        Map<String, String> res = new HashMap<>();
        res.put("status", "success");
        return ResponseEntity.ok(res);
    }

    @PostMapping("/update-policy")
    public ResponseEntity<Map<String, String>> updatePolicy(
            @RequestBody UpdatePolicyRequest req,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        Integer userId = getUserIdFromHeader(authHeader);
        if (userId == null) return ResponseEntity.status(401).build();

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
                    throw new RuntimeException("Permission Denied: You do not possess the attribute: " + trimmed);
                }
                if (!trimmed.startsWith("ID:")) validList.add(trimmed);
            }
            validatedTags = String.join(",", validList);
        }

        fileService.updateItemPolicy(req.getId(), validatedTags, userId);
        Map<String, String> res = new HashMap<>();
        res.put("status", "success");
        res.put("policyApplied", validatedTags);
        return ResponseEntity.ok(res);
    }

    @GetMapping("/attributes")
    public ResponseEntity<List<AttributeCatalog>> listAttributes(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        Integer userId = getUserIdFromHeader(authHeader);
        if (userId == null) return ResponseEntity.status(401).build();
        return ResponseEntity.ok(userService.listAttributeCatalog());
    }

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

    @GetMapping("/admin/users")
    public ResponseEntity<List<User>> listAllUsers(
            @RequestHeader(value = "Authorization", required = false) String authHeader) throws Exception {
        Integer adminId = getUserIdFromHeader(authHeader);
        if (adminId == null) return ResponseEntity.status(401).build();
        return ResponseEntity.ok(userService.listAllUsers(adminId));
    }

    @DeleteMapping("/admin/users/{id}")
    public ResponseEntity<Map<String, String>> deleteUser(
            @PathVariable Integer id,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        Integer adminId = getUserIdFromHeader(authHeader);
        if (adminId == null) return ResponseEntity.status(401).build();
        userService.deleteUser(id, adminId);
        Map<String, String> res = new HashMap<>();
        res.put("status", "success");
        return ResponseEntity.ok(res);
    }

    @PostMapping("/admin/subadmin")
    public ResponseEntity<Map<String, String>> createSubAdmin(
            @RequestBody RegisterRequest req,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        Integer adminId = getUserIdFromHeader(authHeader);
        if (adminId == null) return ResponseEntity.status(401).build();
        userService.createSubAdmin(req.getUsername(), req.getEmail(), req.getPassword(), adminId);
        Map<String, String> res = new HashMap<>();
        res.put("status", "success");
        return ResponseEntity.ok(res);
    }

    @PostMapping("/admin/assign-attributes")
    public ResponseEntity<Map<String, String>> assignAttributes(
            @RequestBody AssignAttributesRequest req,
            @RequestHeader(value = "Authorization", required = false) String authHeader) throws Exception {
        Integer adminId = getUserIdFromHeader(authHeader);
        if (adminId == null) return ResponseEntity.status(401).build();
        userService.assignAttributes(req.getTargetUserId(), req.getAttributes(), adminId);
        Map<String, String> res = new HashMap<>();
        res.put("status", "success");
        res.put("newAttributes", req.getAttributes());
        return ResponseEntity.ok(res);
    }

    @PostMapping("/admin/attributes")
    public ResponseEntity<Map<String, String>> addAttribute(
            @RequestBody AttributeRequest req,
            @RequestHeader(value = "Authorization", required = false) String authHeader) throws Exception {
        Integer adminId = getUserIdFromHeader(authHeader);
        if (adminId == null) return ResponseEntity.status(401).build();
        userService.addAttributeToCatalog(req.getName(), req.getDescription(), adminId);
        Map<String, String> res = new HashMap<>();
        res.put("status", "success");
        return ResponseEntity.ok(res);
    }

    @DeleteMapping("/admin/attributes/{id}")
    public ResponseEntity<Map<String, String>> deleteAttribute(
            @PathVariable Integer id,
            @RequestHeader(value = "Authorization", required = false) String authHeader) throws Exception {
        Integer adminId = getUserIdFromHeader(authHeader);
        if (adminId == null) return ResponseEntity.status(401).build();
        userService.deleteAttributeFromCatalog(id, adminId);
        Map<String, String> res = new HashMap<>();
        res.put("status", "success");
        return ResponseEntity.ok(res);
    }

    @GetMapping("/download/{fileId}")
    public ResponseEntity<Resource> downloadFile(
            @PathVariable Integer fileId,
            @RequestParam(required = false) Integer userIdParam,
            @RequestParam(required = false) String password,
            @RequestParam(required = false) String userAttributes,
            @RequestHeader(value = "Authorization", required = false) String authHeader) throws Exception {

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

        if (Boolean.TRUE.equals(fileMeta.getIsDir())) throw new IllegalArgumentException("Cannot download a directory.");
        if (abeData == null) throw new RuntimeException("Encrypted key data missing for this file.");

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
                throw new RuntimeException("Unauthorized: Invalid user credentials.");
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
            if (recoveredKey == null) throw new RuntimeException("Permission Denied: Attributes mismatch.");
            decryptedFile = abeService.decryptAES(encryptedFile, recoveredKey, fileMeta.getAesIv());
        } else {
            ABEService.HybridCiphertext hc = new ABEService.HybridCiphertext();
            hc.aesEncryptedFile = encryptedFile;
            hc.abeEncryptedKey = abeCt;
            hc.iv = fileMeta.getAesIv();
            String[] attrArray = (userAttributes == null || userAttributes.isEmpty()) ? new String[0] : userAttributes.split(",");
            decryptedFile = abeService.decryptFileHybrid(hc, attrArray);
        }

        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment()
                        .filename(fileMeta.getFilename(), java.nio.charset.StandardCharsets.UTF_8).build().toString())
                .body(new ByteArrayResource(decryptedFile));
    }

    private Integer getUserIdFromHeader(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) return null;
        try {
            return Integer.parseInt(jwtUtil.getUserIdFromToken(authHeader.substring(7)));
        } catch (Exception e) {
            return null;
        }
    }
}
