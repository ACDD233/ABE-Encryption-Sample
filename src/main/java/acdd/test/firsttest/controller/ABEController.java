package acdd.test.firsttest.controller;

import acdd.test.firsttest.common.util.JwtUtil;
import acdd.test.firsttest.entity.FileAbeData;
import acdd.test.firsttest.entity.FileMetadata;
import acdd.test.firsttest.entity.User;
import acdd.test.firsttest.entity.UserKey;
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
    public ResponseEntity<Map<String, Object>> login(@RequestParam String email, @RequestParam String password) {
        try {
            return ResponseEntity.ok(userService.login(email, password));
        } catch (Exception e) {
            Map<String, Object> res = new HashMap<>();
            res.put("error", e.getMessage());
            return ResponseEntity.status(401).body(res);
        }
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(
            @RequestParam String username, @RequestParam String email, @RequestParam String password) {
        try {
            return ResponseEntity.ok(userService.register(username, email, password));
        } catch (Exception e) {
            Map<String, Object> res = new HashMap<>();
            res.put("error", e.getMessage());
            return ResponseEntity.status(500).body(res);
        }
    }

    @PostMapping("/encrypt-file")
    public ResponseEntity<Map<String, Object>> uploadAndEncrypt(
            @RequestParam("file") MultipartFile file,
            @RequestParam("key") String base64Key,
            @RequestParam(value = "parentId", defaultValue = "0") Integer parentId,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {

        try {
            Integer ownerId = getUserIdFromHeader(authHeader);
            if (ownerId == null) return ResponseEntity.status(401).build();

            // Automate policy assignment based on current user's attributes
            User user = userService.getById(ownerId);
            String userAttrStr = (user != null) ? user.getAttributes() : "";
            String[] tags = (userAttrStr != null && !userAttrStr.isEmpty()) ? userAttrStr.split(",") : new String[0];

            byte[] symmetricKey = Base64.getDecoder().decode(base64Key);
            ABEService.HybridCiphertext hc = abeService.encryptFileHybrid(file.getBytes(), symmetricKey, tags);

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
            metadata.setPolicy(userAttrStr);
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
            res.put("policyApplied", userAttrStr);
            return ResponseEntity.ok(res);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/list")
    public ResponseEntity<List<FileMetadata>> listFiles(
            @RequestParam(value = "parentId", defaultValue = "0") Integer parentId,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        Integer userId = getUserIdFromHeader(authHeader);
        if (userId == null) return ResponseEntity.status(401).build();
        return ResponseEntity.ok(fileService.listFiles(parentId, userId));
    }

    @PostMapping("/mkdir")
    public ResponseEntity<Map<String, String>> createDirectory(
            @RequestParam String name,
            @RequestParam(value = "parentId", defaultValue = "0") Integer parentId,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        Integer userId = getUserIdFromHeader(authHeader);
        if (userId == null) return ResponseEntity.status(401).build();

        // Automatically use user's attributes as folder policy
        User user = userService.getById(userId);
        String userAttrStr = (user != null) ? user.getAttributes() : "";

        fileService.createDirectory(name, parentId, userAttrStr, userId);
        Map<String, String> res = new HashMap<>();
        res.put("status", "success");
        res.put("policyApplied", userAttrStr);
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
                for (String attr : user.getAttributes().split(",")) {
                    ABEService.SKComponent comp = new ABEService.SKComponent();
                    comp.attribute = attr.trim();
                    sk.components.add(comp);
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
