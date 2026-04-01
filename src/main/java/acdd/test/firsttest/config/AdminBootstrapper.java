package acdd.test.firsttest.config;

import acdd.test.firsttest.entity.User;
import acdd.test.firsttest.entity.UserKey;
import acdd.test.firsttest.mapper.UserKeyMapper;
import acdd.test.firsttest.mapper.UserMapper;
import acdd.test.firsttest.service.ABEService;
import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class AdminBootstrapper {

    @Autowired
    private UserMapper userMapper;

    @Autowired
    private UserKeyMapper userKeyMapper;

    @Autowired
    private ABEService abeService;

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @PostConstruct
    public void init() {
        // Check if any admin exists
        Long adminCount = userMapper.selectCount(new LambdaQueryWrapper<User>().eq(User::getRole, "ADMIN"));
        
        if (adminCount == 0) {
            System.out.println("No admin found. Initializing default admin...");
            
            String adminEmail = "admin@abe.com";
            String adminPass = "admin123"; // In production, these should be from env variables
            String adminUuid = "ID:ADMIN-" + UUID.randomUUID();

            User admin = new User();
            admin.setUsername("SuperAdmin");
            admin.setEmail(adminEmail);
            admin.setPasswordHash(passwordEncoder.encode(adminPass));
            admin.setRole("ADMIN");
            admin.setAttributes(adminUuid);
            userMapper.insert(admin);

            // Generate ABE Key for Admin
            ABEService.SecretKeyContainer sk = abeService.keygen(new String[]{adminUuid});
            UserKey userKey = new UserKey();
            userKey.setUserId(admin.getId());
            userKey.setSkD(sk.getDBytes());
            userKey.setSkDr(sk.getDrBytes());
            userKeyMapper.insert(userKey);

            System.out.println("=========================================");
            System.out.println("DEFAULT ADMIN CREATED:");
            System.out.println("Email: " + adminEmail);
            System.out.println("Password: " + adminPass);
            System.out.println("=========================================");
        }
    }
}
