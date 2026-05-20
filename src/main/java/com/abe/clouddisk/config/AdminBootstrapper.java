/*
 * Copyright (C) 2026 ACDD233
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package com.abe.clouddisk.config;

import com.abe.clouddisk.entity.User;
import com.abe.clouddisk.entity.UserKey;
import com.abe.clouddisk.mapper.UserKeyMapper;
import com.abe.clouddisk.mapper.UserMapper;
import com.abe.clouddisk.service.ABEService;
import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.UUID;

/**
 * Component responsible for bootstrapping a default administrator account upon system startup.
 * Ensures that at least one administrative account exists for initial system configuration.
 */
@Component
public class AdminBootstrapper {

    /** Mapper for user-related database operations. */
    @Autowired
    private UserMapper userMapper;

    /** Mapper for user cryptographic key operations. */
    @Autowired
    private UserKeyMapper userKeyMapper;

    /** Service for Attribute-Based Encryption operations. */
    @Autowired
    private ABEService abeService;

    /** Encoder for password hashing. */
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    /**
     * Initializes the default administrator account if no admin accounts are found in the database.
     * Generates a random identity tag and ABE secret keys for the new administrator.
     */
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
