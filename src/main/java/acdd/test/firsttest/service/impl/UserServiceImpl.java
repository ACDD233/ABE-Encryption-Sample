package acdd.test.firsttest.service.impl;

import acdd.test.firsttest.common.util.JwtUtil;
import acdd.test.firsttest.entity.User;
import acdd.test.firsttest.entity.UserKey;
import acdd.test.firsttest.mapper.UserKeyMapper;
import acdd.test.firsttest.mapper.UserMapper;
import acdd.test.firsttest.service.ABEService;
import acdd.test.firsttest.service.UserService;
import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserMapper userMapper;

    @Autowired
    private UserKeyMapper userKeyMapper;

    @Autowired
    private ABEService abeService;

    @Autowired
    private JwtUtil jwtUtil;

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Override
    @Transactional
    public Map<String, Object> register(String username, String email, String password) {
        String userUuid = UUID.randomUUID().toString();
        String hashedPassword = passwordEncoder.encode(password);

        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPasswordHash(hashedPassword);
        user.setAttributes(userUuid);
        userMapper.insert(user);

        // ABE Key Generation
        ABEService.SecretKeyContainer sk = abeService.keygen(new String[]{userUuid});
        UserKey userKey = new UserKey();
        userKey.setUserId(user.getId());
        userKey.setSkD(sk.getDBytes());
        userKey.setSkDr(sk.getDrBytes());
        userKeyMapper.insert(userKey);

        Map<String, Object> result = new HashMap<>();
        result.put("userId", user.getId());
        result.put("username", username);
        result.put("initialAttribute", userUuid);
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
        result.put("token", token);
        return result;
    }

    @Override
    public User getById(Integer id) {
        return userMapper.selectById(id);
    }
}
