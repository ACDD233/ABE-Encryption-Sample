package acdd.test.firsttest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/abe")
@CrossOrigin(origins = "*")
public class ABEController {

    @Autowired
    private CompleteFileABE abeService;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Value("${file.upload-dir}")
    private String uploadDir;

    /**
     * Endpoint to receive a file, a symmetric key, and ABE policy tags.
     * Performs hybrid encryption, saves the file to disk, and records metadata in DB.
     */
    @PostMapping("/encrypt-file")
    @Transactional
    public ResponseEntity<Map<String, Object>> uploadAndEncrypt(
            @RequestParam("file") MultipartFile file,
            @RequestParam("key") String base64Key,
            @RequestParam("tags") String[] tags,
            @RequestParam(value = "ownerId", defaultValue = "1") Integer ownerId) {

        Map<String, Object> response = new HashMap<>();

        try {
            if (file.isEmpty()) {
                response.put("error", "File is empty.");
                return ResponseEntity.badRequest().body(response);
            }

            // 1. Decode symmetric key
            byte[] symmetricKey = Base64.getDecoder().decode(base64Key);
            byte[] fileBytes = file.getBytes();

            // 2. Perform Hybrid Encryption
            CompleteFileABE.HybridCiphertext hc = abeService.encryptFileHybrid(fileBytes, symmetricKey, tags);

            // 3. Save the encrypted file to disk
            File dir = new File(uploadDir);
            if (!dir.exists()) dir.mkdirs();

            String uniqueFileName = UUID.randomUUID().toString() + ".enc";
            String fullPath = Paths.get(uploadDir, uniqueFileName).toString();

            try (FileOutputStream fos = new FileOutputStream(fullPath)) {
                fos.write(hc.aesEncryptedFile);
            }

            // 4. Save metadata to Database (files table)
            String policyStr = String.join(",", tags);
            KeyHolder keyHolder = new GeneratedKeyHolder();

            jdbcTemplate.update(connection -> {
                PreparedStatement ps = connection.prepareStatement(
                    "INSERT INTO files (owner_id, filename, file_path, aes_iv, policy) VALUES (?, ?, ?, ?, ?)",
                    Statement.RETURN_GENERATED_KEYS);
                ps.setInt(1, ownerId);
                ps.setString(2, file.getOriginalFilename());
                ps.setString(3, fullPath);
                ps.setBytes(4, hc.iv);
                ps.setString(5, policyStr);
                return ps;
            }, keyHolder);

            Number fileId = keyHolder.getKey();
            if (fileId == null) throw new RuntimeException("Failed to save file metadata.");

            // 5. Save ABE-encrypted key data to Database (file_abe_data table)
            jdbcTemplate.update(
                "INSERT INTO file_abe_data (file_id, encrypted_session_key, ct_c, ct_c_prime) VALUES (?, ?, ?, ?)",
                fileId.intValue(),
                hc.abeEncryptedKey.encryptedSessionKey,
                hc.abeEncryptedKey.getCBytes(),
                hc.abeEncryptedKey.getCPrimeBytes()
            );

            response.put("status", "success");
            response.put("fileId", fileId);
            response.put("savedPath", fullPath);
            response.put("filename", file.getOriginalFilename());

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            e.printStackTrace();
            response.put("status", "error");
            response.put("message", e.getMessage());
            return ResponseEntity.internalServerError().body(response);
        }
    }

    /**
     * Download and decrypt endpoint.
     * Returns the decrypted file as a binary stream (downloadable).
     */
    @GetMapping("/download/{fileId}")
    public ResponseEntity<Resource> downloadAndDecrypt(
            @PathVariable("fileId") Integer fileId,
            @RequestParam("userAttributes") String[] userAttributes) {

        try {
            // 1. Fetch file metadata and ABE data from DB
            Map<String, Object> fileData = jdbcTemplate.queryForMap(
                "SELECT f.file_path, f.aes_iv, f.filename, fd.encrypted_session_key, fd.ct_c, fd.ct_c_prime " +
                "FROM files f JOIN file_abe_data fd ON f.id = fd.file_id WHERE f.id = ?", fileId);

            String filePath = (String) fileData.get("file_path");
            byte[] aesIv = (byte[]) fileData.get("aes_iv");
            String originalName = (String) fileData.get("filename");
            
            CompleteFileABE.ABECiphertext abeCt = new CompleteFileABE.ABECiphertext();
            abeCt.encryptedSessionKey = (byte[]) fileData.get("encrypted_session_key");
            abeCt.setCBytes((byte[]) fileData.get("ct_c"));
            abeCt.setCPrimeBytes((byte[]) fileData.get("ct_c_prime"));

            // 2. Read encrypted file from disk
            byte[] encryptedFile = Files.readAllBytes(Paths.get(filePath));

            // 3. Reconstruct HybridCiphertext
            CompleteFileABE.HybridCiphertext hc = new CompleteFileABE.HybridCiphertext();
            hc.aesEncryptedFile = encryptedFile;
            hc.abeEncryptedKey = abeCt;
            hc.iv = aesIv;

            // 4. Decrypt
            byte[] decryptedFile = abeService.decryptFileHybrid(hc, userAttributes);

            // 5. Build response as a downloadable file
            ByteArrayResource resource = new ByteArrayResource(decryptedFile);
            
            // Detect content type from filename
            String contentType = "application/octet-stream";
            try {
                contentType = Files.probeContentType(Paths.get(originalName));
                if (contentType == null) contentType = "application/octet-stream";
            } catch (Exception e) {
                // Ignore probe errors
            }

            return ResponseEntity.ok()
                    .contentType(MediaType.parseMediaType(contentType))
                    .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment()
                            .filename(originalName, java.nio.charset.StandardCharsets.UTF_8)
                            .build().toString())
                    .body(resource);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().build();
        }
    }
}
