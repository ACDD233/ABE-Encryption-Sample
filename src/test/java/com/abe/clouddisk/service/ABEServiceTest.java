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
package com.abe.clouddisk.service;

import com.abe.clouddisk.service.ABEService.HybridCiphertext;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for the ABEService implementation.
 * These tests verify the actual mathematical operations of ABE and the integration with AES.
 * An H2 in-memory database is used to store system and user keys during the test.
 */
@SpringBootTest
@ActiveProfiles("test")
public class ABEServiceTest {

    @Autowired
    private ABEService abeService;

    /**
     * Verifies the full Attribute-Based Encryption and Decryption lifecycle.
     * This test ensures that:
     * 1. A file can be encrypted with a specific attribute policy.
     * 2. A user with matching attributes can successfully decrypt the file.
     * 3. A user with insufficient attributes is denied access.
     *
     * @throws Exception if any encryption or decryption operation fails unexpectedly.
     */
    @Test
    public void testABEEncryptionDecryptionFlow() throws Exception {
        // 1. Prepare data and policy
        String content = "Sensitive Data for ABE Test";
        byte[] fileBytes = content.getBytes(StandardCharsets.UTF_8);
        byte[] symmetricKey = new byte[32]; // 256-bit AES key
        new java.security.SecureRandom().nextBytes(symmetricKey);
        
        String[] policy = {"Dep:Finance", "Role:Manager"};
        
        // 2. Encrypt File Hybrid (ABE + AES)
        HybridCiphertext hc = abeService.encryptFileHybrid(fileBytes, symmetricKey, policy);
        assertNotNull(hc.aesEncryptedFile);
        assertNotNull(hc.abeEncryptedKey);
        assertNotNull(hc.iv);

        // 3. Test Decryption - Success Scenario (User has all required attributes)
        String[] userAttributesMatch = {"Dep:Finance", "Role:Manager", "ID:USER-123"};
        byte[] decryptedMatch = abeService.decryptFileHybrid(hc, userAttributesMatch);
        assertEquals(content, new String(decryptedMatch, StandardCharsets.UTF_8), "Decryption should succeed with matching attributes");

        // 4. Test Decryption - Failure Scenario (User is missing one attribute)
        String[] userAttributesFail = {"Dep:Finance", "ID:USER-123"}; // Missing "Role:Manager"
        assertThrows(RuntimeException.class, () -> abeService.decryptFileHybrid(hc, userAttributesFail), "Decryption should fail when attributes do not satisfy the policy");
    }

    /**
     * Verifies the standalone AES-GCM encryption and decryption logic.
     * This ensures that the symmetric encryption component is functioning correctly 
     * independently of the ABE layer.
     *
     * @throws Exception if AES encryption or decryption fails.
     */
    @Test
    public void testSymmetricEncryptionOnly() throws Exception {
        String data = "Simple AES Test";
        byte[] key = new byte[32];
        byte[] iv = new byte[12];
        new java.security.SecureRandom().nextBytes(key);
        new java.security.SecureRandom().nextBytes(iv);

        byte[] encrypted = abeService.encryptAES(data.getBytes(), key, iv);
        byte[] decrypted = abeService.decryptAES(encrypted, key, iv);

        assertEquals(data, new String(decrypted), "AES GCM encryption/decryption should work");
    }
}
