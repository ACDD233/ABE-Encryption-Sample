package com.abe.clouddisk.service.impl;

import com.abe.clouddisk.common.util.JwtUtil;
import com.abe.clouddisk.entity.AttributeCatalog;
import com.abe.clouddisk.entity.User;
import com.abe.clouddisk.entity.UserKey;
import com.abe.clouddisk.mapper.AttributeCatalogMapper;
import com.abe.clouddisk.mapper.UserKeyMapper;
import com.abe.clouddisk.mapper.UserMapper;
import com.abe.clouddisk.service.ABEService;
import com.abe.clouddisk.service.FileService;
import com.abe.clouddisk.service.UserService;
import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Implementation of the {@link UserService} providing concrete logic for user management and security.
 * This service coordinates with ABE and File services to ensure consistent cryptographic state.
 */
@Service
public class UserServiceImpl implements UserService {

    /** Mapper for user-related database operations. */
    @Autowired
    private UserMapper userMapper;

    /** Mapper for user cryptographic key operations. */
    @Autowired
    private UserKeyMapper userKeyMapper;

    /** Mapper for system attribute catalog operations. */
    @Autowired
    private AttributeCatalogMapper attributeCatalogMapper;

    /** Service for Attribute-Based Encryption operations. */
    @Autowired
    private ABEService abeService;

    /** Service for file management operations. */
    @Autowired
    private FileService fileService;

    /** Utility for JWT token operations. */
    @Autowired
    private JwtUtil jwtUtil;

    /** Encoder for password hashing and verification. */
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    
    /** Regex pattern for validating UUIDs. */
    private static final Pattern UUID_PATTERN = Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

    /**
     * {@inheritDoc}
     * Also generates a unique identity attribute (ID:uuid) for the user and their initial ABE keys.
     */
    @Override
    @Transactional
    public Map<String, Object> register(String username, String email, String password) {
        String userUuid = "ID:" + UUID.randomUUID();
        String hashedPassword = passwordEncoder.encode(password);

        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPasswordHash(hashedPassword);
        user.setRole("USER");
        user.setAttributes(userUuid);
        userMapper.insert(user);

        ABEService.SecretKeyContainer sk = abeService.keygen(new String[]{userUuid});
        UserKey userKey = new UserKey();
        userKey.setUserId(user.getId());
        userKey.setSkD(sk.getDBytes());
        userKey.setSkDr(sk.getDrBytes());
        userKeyMapper.insert(userKey);

        Map<String, Object> result = new HashMap<>();
        result.put("userId", user.getId());
        result.put("username", username);
        result.put("identityTag", userUuid);
        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Map<String, Object> login(String email, String password) {
        User user = userMapper.selectOne(new LambdaQueryWrapper<User>().eq(User::getEmail, email));
        if (user == null || !passwordEncoder.matches(password, user.getPasswordHash())) {
            throw new RuntimeException("Invalid email or password.");
        }

        String token = jwtUtil.generateToken(user.getId().toString(), user.getUsername());

        Map<String, Object> result = new HashMap<>();
        result.put("userId", user.getId());
        result.put("username", user.getUsername());
        result.put("role", user.getRole());
        result.put("attributes", user.getAttributes());
        result.put("token", token);
        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public User getById(Integer id) {
        return userMapper.selectById(id);
    }

    /**
     * {@inheritDoc}
     * Validates that assigned attributes exist in the system catalog and regenerates the user's ABE secret keys.
     */
    @Override
    @Transactional
    public void assignAttributes(Integer userId, String extraAttributes, Integer adminId) {
        User admin = userMapper.selectById(adminId);
        if (admin == null || !"ADMIN".equalsIgnoreCase(admin.getRole())) {
            throw new RuntimeException("Unauthorized: Admin access required.");
        }

        User targetUser = userMapper.selectById(userId);
        if (targetUser == null) throw new RuntimeException("Target user not found.");

        // 1. Validation Logic: Only allow attributes present in the Catalog
        if (extraAttributes != null && !extraAttributes.isEmpty()) {
            Set<String> validAttributes = attributeCatalogMapper.selectList(null).stream()
                    .map(AttributeCatalog::getName)
                    .collect(Collectors.toSet());

            String[] requestedTags = extraAttributes.split(",");
            for (String tag : requestedTags) {
                String trimmed = tag.trim();
                if (trimmed.isEmpty()) continue;
                if (!validAttributes.contains(trimmed)) {
                    throw new RuntimeException("Attribute '" + trimmed + "' does not exist in the system catalog. Please add it first.");
                }
            }
        }

        // 2. Compatibility & Identity Logic
        String currentAttributes = targetUser.getAttributes();
        String identityTag = "";
        
        if (currentAttributes != null && !currentAttributes.isEmpty()) {
            for (String tag : currentAttributes.split(",")) {
                String trimmed = tag.trim();
                if (trimmed.startsWith("ID:")) {
                    identityTag = trimmed;
                    break;
                } else if (UUID_PATTERN.matcher(trimmed).matches()) {
                    identityTag = "ID:" + trimmed;
                    break;
                }
            }
        }

        // 3. Combine identity tag with validated extra tags
        String finalAttributes = identityTag;
        if (extraAttributes != null && !extraAttributes.isEmpty()) {
            finalAttributes = (identityTag.isEmpty() ? "" : identityTag + ",") + extraAttributes;
        }

        targetUser.setAttributes(finalAttributes);
        userMapper.updateById(targetUser);

        // 4. Update ABE Keys
        String[] attrArray = finalAttributes.split(",");
        ABEService.SecretKeyContainer sk = abeService.keygen(attrArray);

        UserKey uk = userKeyMapper.selectById(userId);
        uk.setSkD(sk.getDBytes());
        uk.setSkDr(sk.getDrBytes());
        userKeyMapper.updateById(uk);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<User> listAllUsers(Integer adminId) {
        User admin = userMapper.selectById(adminId);
        if (admin == null || !"ADMIN".equalsIgnoreCase(admin.getRole())) {
            throw new RuntimeException("Unauthorized: Admin access required.");
        }
        return userMapper.selectList(null);
    }

    /**
     * {@inheritDoc}
     * Ensures an admin cannot delete themselves or other administrative accounts.
     */
    @Override
    @Transactional
    public void deleteUser(Integer targetUserId, Integer adminId) {
        // 1. Admin permission check
        User admin = userMapper.selectById(adminId);
        if (admin == null || !"ADMIN".equalsIgnoreCase(admin.getRole())) {
            throw new RuntimeException("Unauthorized: Admin access required.");
        }

        // 2. Self-deletion protection
        if (targetUserId.equals(adminId)) {
            throw new RuntimeException("Safety violation: You cannot delete your own account.");
        }

        // 3. Target existence and Admin-deletion protection
        User targetUser = userMapper.selectById(targetUserId);
        if (targetUser == null) {
            throw new RuntimeException("Target user not found.");
        }
        if ("ADMIN".equalsIgnoreCase(targetUser.getRole())) {
            throw new RuntimeException("Safety violation: Administrative accounts cannot be deleted.");
        }

        // 4. Delete user files
        fileService.deleteUserFiles(targetUserId);

        // 5. Delete user ABE keys
        userKeyMapper.deleteById(targetUserId);

        // 6. Delete user record
        userMapper.deleteById(targetUserId);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    public void addAttributeToCatalog(String name, String description, Integer adminId) {
        User admin = userMapper.selectById(adminId);
        if (admin == null || !"ADMIN".equalsIgnoreCase(admin.getRole())) {
            throw new RuntimeException("Unauthorized: Admin access required.");
        }
        
        AttributeCatalog attr = new AttributeCatalog();
        attr.setName(name);
        attr.setDescription(description);
        attributeCatalogMapper.insert(attr);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    public void deleteAttributeFromCatalog(Integer attributeId, Integer adminId) {
        User admin = userMapper.selectById(adminId);
        if (admin == null || !"ADMIN".equalsIgnoreCase(admin.getRole())) {
            throw new RuntimeException("Unauthorized: Admin access required.");
        }
        attributeCatalogMapper.deleteById(attributeId);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<AttributeCatalog> listAttributeCatalog() {
        return attributeCatalogMapper.selectList(null);
    }
}
