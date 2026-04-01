package acdd.test.firsttest.service.impl;

import acdd.test.firsttest.common.util.JwtUtil;
import acdd.test.firsttest.entity.AttributeCatalog;
import acdd.test.firsttest.entity.User;
import acdd.test.firsttest.entity.UserKey;
import acdd.test.firsttest.mapper.AttributeCatalogMapper;
import acdd.test.firsttest.mapper.UserKeyMapper;
import acdd.test.firsttest.mapper.UserMapper;
import acdd.test.firsttest.service.ABEService;
import acdd.test.firsttest.service.UserService;
import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserMapper userMapper;

    @Autowired
    private UserKeyMapper userKeyMapper;

    @Autowired
    private AttributeCatalogMapper attributeCatalogMapper;

    @Autowired
    private ABEService abeService;

    @Autowired
    private JwtUtil jwtUtil;

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    private static final Pattern UUID_PATTERN = Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

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
        result.put("token", token);
        return result;
    }

    @Override
    public User getById(Integer id) {
        return userMapper.selectById(id);
    }

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

    @Override
    public List<User> listAllUsers(Integer adminId) {
        User admin = userMapper.selectById(adminId);
        if (admin == null || !"ADMIN".equalsIgnoreCase(admin.getRole())) {
            throw new RuntimeException("Unauthorized: Admin access required.");
        }
        return userMapper.selectList(null);
    }

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

    @Override
    @Transactional
    public void deleteAttributeFromCatalog(Integer attributeId, Integer adminId) {
        User admin = userMapper.selectById(adminId);
        if (admin == null || !"ADMIN".equalsIgnoreCase(admin.getRole())) {
            throw new RuntimeException("Unauthorized: Admin access required.");
        }
        attributeCatalogMapper.deleteById(attributeId);
    }

    @Override
    public List<AttributeCatalog> listAttributeCatalog() {
        return attributeCatalogMapper.selectList(null);
    }
}
