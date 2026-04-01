package acdd.test.firsttest.controller;

import acdd.test.firsttest.common.util.JwtUtil;
import acdd.test.firsttest.dto.*;
import acdd.test.firsttest.entity.*;
import acdd.test.firsttest.mapper.UserKeyMapper;
import acdd.test.firsttest.service.ABEService;
import acdd.test.firsttest.service.FileService;
import acdd.test.firsttest.service.UserService;
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

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

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

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody LoginRequest req) {
        try {
            return ResponseEntity.ok(userService.login(req.email, req.password));
        } catch (Exception e) {
            Map<String, Object> res = new HashMap<>();
            res.put("error", e.getMessage());
            return ResponseEntity.status(401).body(res);
        }
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@RequestBody RegisterRequest req) {
        try {
            return ResponseEntity.ok(userService.register(req.username, req.email, req.password));
        } catch (Exception e) {
            Map<String, Object> res = new HashMap<>();
            res.put("error", e.getMessage());
            return ResponseEntity.status(500).body(res);
        }
    }

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

            File dir = new File(uploadDir);
            if (!dir.exists()) dir.mkdirs();

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
            e.printStackTrace();
            return ResponseEntity.internalServerError().build();
        }
    }

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

    @PostMapping("/share")
    public ResponseEntity<Map<String, String>> shareFile(
            @RequestBody ShareRequest req,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        Integer userId = getUserIdFromHeader(authHeader);
        if (userId == null) return ResponseEntity.status(401).build();

        try {
            // Validation: Only allow sharing to tags present in Catalog (or ID: personal tags)
            if (req.targetPolicy != null && !req.targetPolicy.isEmpty()) {
                Set<String> validAttributes = userService.listAttributeCatalog().stream()
                        .map(AttributeCatalog::getName)
                        .collect(Collectors.toSet());

                String[] tags = req.targetPolicy.split(",");
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

            fileService.shareFile(req.fileId, req.targetPolicy, userId);
            Map<String, String> res = new HashMap<>();
            res.put("status", "success");
            return ResponseEntity.ok(res);
        } catch (Exception e) {
            Map<String, String> res = new HashMap<>();
            res.put("error", e.getMessage());
            return ResponseEntity.status(500).body(res);
        }
    }

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
            if (req.selectedTags != null && !req.selectedTags.isEmpty()) {
                String[] requested = req.selectedTags.split(",");
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

            fileService.updateItemPolicy(req.id, validatedTags, userId);
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

    @GetMapping("/attributes")
    public ResponseEntity<List<AttributeCatalog>> listAttributes(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        Integer userId = getUserIdFromHeader(authHeader);
        if (userId == null) return ResponseEntity.status(401).build();
        return ResponseEntity.ok(userService.listAttributeCatalog());
    }

    // Admin APIs
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

    @PostMapping("/admin/assign-attributes")
    public ResponseEntity<Map<String, String>> assignAttributes(
            @RequestBody AssignAttributesRequest req,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        Integer adminId = getUserIdFromHeader(authHeader);
        if (adminId == null) return ResponseEntity.status(401).build();

        try {
            userService.assignAttributes(req.targetUserId, req.attributes, adminId);
            Map<String, String> res = new HashMap<>();
            res.put("status", "success");
            res.put("newAttributes", req.attributes);
            return ResponseEntity.ok(res);
        } catch (Exception e) {
            Map<String, String> res = new HashMap<>();
            res.put("error", e.getMessage());
            return ResponseEntity.status(403).body(res);
        }
    }

    @PostMapping("/admin/attributes")
    public ResponseEntity<Map<String, String>> addAttribute(
            @RequestBody AttributeRequest req,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        Integer adminId = getUserIdFromHeader(authHeader);
        if (adminId == null) return ResponseEntity.status(401).build();

        try {
            userService.addAttributeToCatalog(req.name, req.description, adminId);
            Map<String, String> res = new HashMap<>();
            res.put("status", "success");
            return ResponseEntity.ok(res);
        } catch (Exception e) {
            Map<String, String> res = new HashMap<>();
            res.put("error", e.getMessage());
            return ResponseEntity.status(403).body(res);
        }
    }

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

    private Integer getUserIdFromHeader(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) return null;
        try {
            return Integer.parseInt(jwtUtil.getUserIdFromToken(authHeader.substring(7)));
        } catch (Exception e) {
            return null;
        }
    }

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
            if (data == null) return ResponseEntity.notFound().build();

            FileMetadata fileMeta = (FileMetadata) data.get("file");
            FileAbeData abeData = (FileAbeData) data.get("abeData");

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
            e.printStackTrace();
            return ResponseEntity.internalServerError().build();
        }
    }
}
