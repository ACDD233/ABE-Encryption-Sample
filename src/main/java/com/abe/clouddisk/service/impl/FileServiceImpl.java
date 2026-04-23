package com.abe.clouddisk.service.impl;

import com.abe.clouddisk.entity.*;
import com.abe.clouddisk.mapper.*;
import com.abe.clouddisk.service.ABEService;
import com.abe.clouddisk.service.FileService;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Implementation of the {@link FileService} providing concrete logic for file and directory management.
 * This service handles metadata persistence, file system operations, and ABE policy propagation.
 */
@Slf4j
@Service
public class FileServiceImpl implements FileService {

    /** Mapper for file metadata operations. */
    @Autowired
    private FileMetadataMapper fileMetadataMapper;

    /** Mapper for ABE ciphertext data operations. */
    @Autowired
    private FileAbeDataMapper fileAbeDataMapper;

    /** Mapper for user-related database operations. */
    @Autowired
    private UserMapper userMapper;

    /** Mapper for user cryptographic key operations. */
    @Autowired
    private UserKeyMapper userKeyMapper;

    /** Service for Attribute-Based Encryption operations. */
    @Autowired
    private ABEService abeService;

    /** Regex pattern for validating UUIDs, used to identify identity-based attributes. */
    private static final Pattern UUID_PATTERN = Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    public void saveFileMetadata(FileMetadata fileMetadata, FileAbeData abeData) {
        if (fileMetadata.getIsDir() == null) fileMetadata.setIsDir(false);
        fileMetadataMapper.insert(fileMetadata);
        if (abeData != null) {
            abeData.setFileId(fileMetadata.getId());
            fileAbeDataMapper.insert(abeData);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Map<String, Object> getFileAndAbeData(Integer fileId) {
        FileMetadata file = fileMetadataMapper.selectById(fileId);
        FileAbeData abeData = fileAbeDataMapper.selectById(fileId);
        if (file == null) return null;
        Map<String, Object> result = new HashMap<>();
        result.put("file", file);
        result.put("abeData", abeData);
        return result;
    }

    /**
     * {@inheritDoc}
     * Directories inherit policies from their parents and add an identity-based tag.
     */
    @Override
    public Integer createDirectory(String name, Integer parentId, String policy, Integer ownerId) {
        String finalPolicy = policy;
        if (parentId != null && parentId != 0) {
            FileMetadata parent = fileMetadataMapper.selectById(parentId);
            if (parent == null || !Boolean.TRUE.equals(parent.getIsDir())) {
                throw new RuntimeException("Target parent is not a directory.");
            }
            User user = userMapper.selectById(ownerId);
            if (!abeService.isPolicySatisfied(parent.getPolicy(), user.getAttributes())) {
                throw new RuntimeException("Permission denied: You cannot create items in a directory you cannot access.");
            }
            finalPolicy = mergePolicies(parent.getPolicy(), policy);
        }

        FileMetadata dir = new FileMetadata();
        dir.setFilename(name);
        dir.setParentId(parentId == null ? 0 : parentId);
        dir.setPolicy(finalPolicy);
        dir.setOwnerId(ownerId);
        dir.setIsDir(true);
        dir.setUploadTime(LocalDateTime.now());
        dir.setFilePath("");
        dir.setAesIv(new byte[16]);
        fileMetadataMapper.insert(dir);
        return dir.getId();
    }

    /**
     * {@inheritDoc}
     * Only returns items that the user owns or has sufficient attributes to access via ABE.
     */
    @Override
    public List<FileMetadata> listFiles(Integer parentId, Integer userId) {
        User user = userMapper.selectById(userId);
        String userAttributes = (user != null) ? user.getAttributes() : "";

        if (parentId != null && parentId != 0) {
            FileMetadata parent = fileMetadataMapper.selectById(parentId);
            if (parent == null) throw new RuntimeException("Directory not found.");
            if (!Boolean.TRUE.equals(parent.getIsDir())) throw new RuntimeException("Requested item is not a directory.");
            if (!parent.getOwnerId().equals(userId) && !abeService.isPolicySatisfied(parent.getPolicy(), userAttributes)) {
                throw new RuntimeException("Access Denied: You do not have permission to access this directory.");
            }
        }

        QueryWrapper<FileMetadata> queryWrapper = new QueryWrapper<>();
        queryWrapper.eq("parent_id", parentId == null ? 0 : parentId);
        List<FileMetadata> allItems = fileMetadataMapper.selectList(queryWrapper);

        return allItems.stream()
                .filter(item -> item.getOwnerId().equals(userId) || abeService.isPolicySatisfied(item.getPolicy(), userAttributes))
                .collect(Collectors.toList());
    }

    /**
     * {@inheritDoc}
     * Recursively deletes directories and their contents from the database and file system.
     */
    @Override
    @Transactional
    public void deleteItem(Integer id, Integer userId) {
        FileMetadata item = fileMetadataMapper.selectById(id);
        if (item == null) return;
        
        if (!item.getOwnerId().equals(userId)) {
            throw new RuntimeException("Unauthorized: You are not the owner of this item.");
        }
        deleteItemInternal(item);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    public void deleteUserFiles(Integer userId) {
        QueryWrapper<FileMetadata> queryWrapper = new QueryWrapper<>();
        queryWrapper.eq("owner_id", userId);
        List<FileMetadata> userFiles = fileMetadataMapper.selectList(queryWrapper);
        for (FileMetadata item : userFiles) {
            // Check if item still exists (it might have been deleted if it was inside a deleted parent directory)
            if (fileMetadataMapper.selectById(item.getId()) != null) {
                deleteItemInternal(item);
            }
        }
    }

    /**
     * Internal recursive method to delete an item and its children.
     *
     * @param item The item to delete.
     */
    private void deleteItemInternal(FileMetadata item) {
        if (Boolean.TRUE.equals(item.getIsDir())) {
            List<FileMetadata> children = fileMetadataMapper.selectList(new QueryWrapper<FileMetadata>().eq("parent_id", item.getId()));
            for (FileMetadata child : children) {
                deleteItemInternal(child);
            }
        } else {
            String filePath = item.getFilePath();
            if (filePath != null && !filePath.isEmpty()) {
                if (fileMetadataMapper.selectCount(new QueryWrapper<FileMetadata>().eq("file_path", filePath)) <= 1) {
                    try {
                        Files.deleteIfExists(Paths.get(filePath));
                    } catch (IOException e) {
                        log.error("Failed to delete physical file: {}", filePath, e);
                    }
                }
            }
            fileAbeDataMapper.deleteById(item.getId());
        }
        fileMetadataMapper.deleteById(item.getId());
    }

    /**
     * {@inheritDoc}
     * Moves an item and updates its policy (and children's policies) based on the new parent.
     */
    @Override
    @Transactional
    public void moveItem(Integer id, Integer targetParentId, Integer userId) {
        FileMetadata item = fileMetadataMapper.selectById(id);
        if (item == null || !item.getOwnerId().equals(userId)) throw new RuntimeException("Unauthorized or not found.");

        User user = userMapper.selectById(userId);
        String userAttributes = user.getAttributes();

        String newParentPolicy = "";
        if (targetParentId != 0) {
            FileMetadata targetParent = fileMetadataMapper.selectById(targetParentId);
            if (targetParent == null || !Boolean.TRUE.equals(targetParent.getIsDir())) {
                throw new RuntimeException("Invalid target directory.");
            }
            if (!abeService.isPolicySatisfied(targetParent.getPolicy(), userAttributes)) {
                throw new RuntimeException("Permission denied: You do not have access to the target directory.");
            }
            newParentPolicy = targetParent.getPolicy();
        }
        
        String oldParentPolicy = "";
        if (item.getParentId() != 0) {
            FileMetadata oldParent = fileMetadataMapper.selectById(item.getParentId());
            if (oldParent != null) oldParentPolicy = oldParent.getPolicy();
        }

        updatePolicySmartRecursive(item, oldParentPolicy, newParentPolicy, userId);
        item.setParentId(targetParentId);
        fileMetadataMapper.updateById(item);
    }

    /**
     * {@inheritDoc}
     * Creates a deep copy of the item and its contents, re-encrypting files for the new location's policy.
     */
    @Override
    @Transactional
    public void copyItem(Integer id, Integer targetParentId, Integer userId) {
        FileMetadata item = fileMetadataMapper.selectById(id);
        if (item == null || !item.getOwnerId().equals(userId)) throw new RuntimeException("Unauthorized or not found.");

        User user = userMapper.selectById(userId);
        String targetParentPolicy = "";
        if (targetParentId != 0) {
            FileMetadata targetParent = fileMetadataMapper.selectById(targetParentId);
            if (targetParent == null || !Boolean.TRUE.equals(targetParent.getIsDir())) {
                throw new RuntimeException("Invalid target directory.");
            }
            if (!abeService.isPolicySatisfied(targetParent.getPolicy(), user.getAttributes())) {
                throw new RuntimeException("Permission denied: You do not have access to the target directory.");
            }
            targetParentPolicy = targetParent.getPolicy();
        }

        copySmartRecursive(item, targetParentId, targetParentPolicy, userId);
    }

    /**
     * {@inheritDoc}
     * Shares a file or directory by creating a reference with a different ABE policy.
     */
    @Override
    @Transactional
    public void shareFile(Integer id, String targetPolicy, Integer userId) {
        FileMetadata item = fileMetadataMapper.selectById(id);
        if (item == null || !item.getOwnerId().equals(userId)) throw new RuntimeException("Unauthorized or not found.");
        shareRecursive(item, 0, targetPolicy, userId);
    }

    /**
     * {@inheritDoc}
     * Updates the custom tags of an item and propagates the change to children.
     */
    @Override
    @Transactional
    public void updateItemPolicy(Integer id, String newCustomTags, Integer userId) {
        FileMetadata item = fileMetadataMapper.selectById(id);
        if (item == null || !item.getOwnerId().equals(userId)) throw new RuntimeException("Unauthorized or not found.");

        String parentPolicy = "";
        if (item.getParentId() != 0) {
            FileMetadata parent = fileMetadataMapper.selectById(item.getParentId());
            if (parent != null) parentPolicy = parent.getPolicy();
        }

        String identityTag = extractIdentityTag(item.getPolicy());
        String finalPolicy = mergePolicies(mergePolicies(parentPolicy, identityTag), newCustomTags);

        updatePolicyValueRecursive(item, finalPolicy, userId);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    public void renameItem(Integer id, String newName, Integer userId) {
        FileMetadata item = fileMetadataMapper.selectById(id);
        if (item == null || !item.getOwnerId().equals(userId)) {
            throw new RuntimeException("Unauthorized or not found.");
        }
        item.setFilename(newName);
        fileMetadataMapper.updateById(item);
    }

    // --- Private Smart Helper Methods ---

    /**
     * Recursively updates the policy of an item by stripping the old parent's policy and adding the new parent's policy.
     *
     * @param item            The item to update.
     * @param oldParentPolicy The policy of the former parent.
     * @param newParentPolicy The policy of the new parent.
     * @param userId          The ID of the user performing the operation.
     */
    private void updatePolicySmartRecursive(FileMetadata item, String oldParentPolicy, String newParentPolicy, Integer userId) {
        String currentPolicy = item.getPolicy();
        String strippedPolicy = stripPolicy(currentPolicy, oldParentPolicy);
        String finalPolicy = mergePolicies(newParentPolicy, strippedPolicy);

        if (Boolean.TRUE.equals(item.getIsDir())) {
            item.setPolicy(finalPolicy);
            fileMetadataMapper.updateById(item);
            List<FileMetadata> children = fileMetadataMapper.selectList(new QueryWrapper<FileMetadata>().eq("parent_id", item.getId()));
            for (FileMetadata child : children) {
                updatePolicySmartRecursive(child, oldParentPolicy, newParentPolicy, userId);
            }
        } else {
            if (!finalPolicy.equals(currentPolicy)) {
                reEncryptFile(item, finalPolicy, userId);
                item.setPolicy(finalPolicy);
                fileMetadataMapper.updateById(item);
            }
        }
    }

    /**
     * Recursively copies an item and its children.
     *
     * @param item           The item to copy.
     * @param targetParentId The target parent ID for the copy.
     * @param parentPolicy   The policy of the target parent.
     * @param userId         The ID of the user performing the copy.
     */
    private void copySmartRecursive(FileMetadata item, Integer targetParentId, String parentPolicy, Integer userId) {
        String identityTag = extractIdentityTag(item.getPolicy());
        String finalPolicy = mergePolicies(parentPolicy, identityTag);

        FileMetadata newItem = new FileMetadata();
        newItem.setFilename(item.getFilename() + (targetParentId.equals(item.getParentId()) ? " (Copy)" : ""));
        newItem.setParentId(targetParentId);
        newItem.setOwnerId(userId);
        newItem.setPolicy(finalPolicy);
        newItem.setIsDir(item.getIsDir());
        newItem.setUploadTime(LocalDateTime.now());
        newItem.setFilePath(item.getFilePath());
        newItem.setAesIv(item.getAesIv());
        fileMetadataMapper.insert(newItem);

        if (Boolean.TRUE.equals(item.getIsDir())) {
            List<FileMetadata> children = fileMetadataMapper.selectList(new QueryWrapper<FileMetadata>().eq("parent_id", item.getId()));
            for (FileMetadata child : children) {
                copySmartRecursive(child, newItem.getId(), finalPolicy, userId);
            }
        } else {
            reEncryptFileForCopy(item, newItem.getId(), finalPolicy, userId);
        }
    }

    /**
     * Recursively updates the policy of an item to an exact value.
     *
     * @param item           The item to update.
     * @param newExactPolicy The new policy value.
     * @param userId         The ID of the user performing the operation.
     */
    private void updatePolicyValueRecursive(FileMetadata item, String newExactPolicy, Integer userId) {
        String oldPolicy = item.getPolicy();
        if (Boolean.TRUE.equals(item.getIsDir())) {
            item.setPolicy(newExactPolicy);
            fileMetadataMapper.updateById(item);
            List<FileMetadata> children = fileMetadataMapper.selectList(new QueryWrapper<FileMetadata>().eq("parent_id", item.getId()));
            for (FileMetadata child : children) {
                String childIdentity = extractIdentityTag(child.getPolicy());
                String childNewPolicy = mergePolicies(newExactPolicy, childIdentity);
                updatePolicyValueRecursive(child, childNewPolicy, userId);
            }
        } else {
            if (!newExactPolicy.equals(oldPolicy)) {
                reEncryptFile(item, newExactPolicy, userId);
                item.setPolicy(newExactPolicy);
                fileMetadataMapper.updateById(item);
            }
        }
    }

    /**
     * Recursively shares an item.
     *
     * @param item             The item to share.
     * @param targetParentId   The parent ID for the shared instance.
     * @param baseSharePolicy  The sharing access policy.
     * @param userId           The ID of the user performing the share.
     */
    private void shareRecursive(FileMetadata item, Integer targetParentId, String baseSharePolicy, Integer userId) {
        FileMetadata shareItem = new FileMetadata();
        shareItem.setFilename(item.getFilename() + (targetParentId == 0 ? " (Shared)" : ""));
        shareItem.setParentId(targetParentId);
        shareItem.setOwnerId(item.getOwnerId());
        shareItem.setPolicy(baseSharePolicy);
        shareItem.setIsDir(item.getIsDir());
        shareItem.setUploadTime(LocalDateTime.now());
        shareItem.setFilePath(item.getFilePath());
        shareItem.setAesIv(item.getAesIv());
        fileMetadataMapper.insert(shareItem);

        if (Boolean.TRUE.equals(item.getIsDir())) {
            List<FileMetadata> children = fileMetadataMapper.selectList(new QueryWrapper<FileMetadata>().eq("parent_id", item.getId()));
            for (FileMetadata child : children) {
                shareRecursive(child, shareItem.getId(), baseSharePolicy, userId);
            }
        } else {
            reEncryptFileForCopy(item, shareItem.getId(), baseSharePolicy, userId);
        }
    }

    /**
     * Re-encrypts the AES session key of a file with a new ABE policy.
     *
     * @param item      The file metadata.
     * @param newPolicy The new access policy.
     * @param userId    The ID of the user performing the operation.
     */
    private void reEncryptFile(FileMetadata item, String newPolicy, Integer userId) {
        try {
            byte[] aesKey = decryptCurrentAesKey(item, userId);
            ABEService.ABECiphertext newCt = abeService.encryptSessionKey(aesKey, newPolicy.split(","));
            FileAbeData abeData = fileAbeDataMapper.selectById(item.getId());
            if (abeData == null) throw new Exception("ABE Data missing for file " + item.getId());
            abeData.setEncryptedSessionKey(newCt.encryptedSessionKey);
            abeData.setCtC(newCt.getCBytes());
            abeData.setCtCPrime(newCt.getCPrimeBytes());
            fileAbeDataMapper.updateById(abeData);
        } catch (Exception e) {
            throw new RuntimeException("Action failed for " + item.getFilename() + ". Reason: " + e.getMessage());
        }
    }

    /**
     * Re-encrypts the AES session key for a newly copied file.
     *
     * @param originalItem The original file metadata.
     * @param newItemId    The ID of the new file copy.
     * @param newPolicy    The access policy for the copy.
     * @param userId       The ID of the user performing the copy.
     */
    private void reEncryptFileForCopy(FileMetadata originalItem, Integer newItemId, String newPolicy, Integer userId) {
        try {
            byte[] aesKey = decryptCurrentAesKey(originalItem, userId);
            ABEService.ABECiphertext newCt = abeService.encryptSessionKey(aesKey, newPolicy.split(","));
            FileAbeData abeData = new FileAbeData();
            abeData.setFileId(newItemId);
            abeData.setEncryptedSessionKey(newCt.encryptedSessionKey);
            abeData.setCtC(newCt.getCBytes());
            abeData.setCtCPrime(newCt.getCPrimeBytes());
            fileAbeDataMapper.insert(abeData);
        } catch (Exception e) {
            throw new RuntimeException("Action failed for " + originalItem.getFilename() + ". Reason: " + e.getMessage());
        }
    }

    /**
     * Decrypts the current AES session key of a file using the user's ABE secret key.
     *
     * @param item   The file metadata.
     * @param userId The ID of the user attempting decryption.
     * @return The recovered AES session key.
     * @throws Exception If decryption fails or attributes do not match.
     */
    private byte[] decryptCurrentAesKey(FileMetadata item, Integer userId) throws Exception {
        FileAbeData abeData = fileAbeDataMapper.selectById(item.getId());
        if (abeData == null) throw new Exception("Encrypted key data not found.");

        UserKey uk = userKeyMapper.selectById(userId);
        User user = userMapper.selectById(userId);

        ABEService.SecretKeyContainer sk = new ABEService.SecretKeyContainer();
        sk.D = abeService.getElementFromBytes(uk.getSkD(), "G1");
        sk.D_r = abeService.getElementFromBytes(uk.getSkDr(), "G1");
        
        // Add all user's attributes
        for (String attr : user.getAttributes().split(",")) {
            String trimmed = attr.trim();
            if (trimmed.isEmpty()) continue;
            ABEService.SKComponent comp = new ABEService.SKComponent();
            comp.attribute = trimmed;
            sk.components.add(comp);
            // Compatibility: If user has ID:uuid, also add plain uuid to secret key to match older files
            if (trimmed.startsWith("ID:")) {
                String plainUuid = trimmed.substring(3);
                ABEService.SKComponent legacyComp = new ABEService.SKComponent();
                legacyComp.attribute = plainUuid;
                sk.components.add(legacyComp);
            }
        }

        ABEService.ABECiphertext abeCt = new ABEService.ABECiphertext();
        abeCt.encryptedSessionKey = abeData.getEncryptedSessionKey();
        abeCt.tempCBytes = abeData.getCtC();
        abeCt.tempCPrimeBytes = abeData.getCtCPrime();
        for (String tag : item.getPolicy().split(",")) {
            String trimmed = tag.trim();
            if (trimmed.isEmpty()) continue;
            ABEService.CTComponent comp = new ABEService.CTComponent();
            comp.attribute = trimmed;
            abeCt.components.add(comp);
        }

        byte[] key = abeService.decryptSessionKey(sk, abeCt);
        if (key == null) throw new Exception("You do not have permission to access the encryption key of this item (Attributes mismatch).");
        return key;
    }

    /**
     * Merges two comma-separated policy strings into one, removing duplicates.
     *
     * @param p1 The first policy string.
     * @param p2 The second policy string.
     * @return The merged policy string.
     */
    private String mergePolicies(String p1, String p2) {
        if (p1 == null || p1.isEmpty()) return p2;
        if (p2 == null || p2.isEmpty()) return p1;
        Set<String> tags = new LinkedHashSet<>();
        tags.addAll(Arrays.stream(p1.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList());
        tags.addAll(Arrays.stream(p2.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList());
        return String.join(",", tags);
    }

    /**
     * Strips attributes of one policy from another.
     *
     * @param fullPolicy The policy to strip from.
     * @param toStrip    The attributes to remove.
     * @return The stripped policy string.
     */
    private String stripPolicy(String fullPolicy, String toStrip) {
        if (fullPolicy == null || toStrip == null || toStrip.isEmpty()) return fullPolicy;
        Set<String> stripSet = Arrays.stream(toStrip.split(",")).map(String::trim).collect(Collectors.toSet());
        return Arrays.stream(fullPolicy.split(","))
                .map(String::trim)
                .filter(t -> !stripSet.contains(t))
                .collect(Collectors.joining(","));
    }

    /**
     * Extracts the identity tag (ID:uuid) from a policy string.
     *
     * @param policy The policy string.
     * @return The identity tag if found, empty string otherwise.
     */
    private String extractIdentityTag(String policy) {
        if (policy == null) return "";
        return Arrays.stream(policy.split(","))
                .map(String::trim)
                .filter(t -> t.startsWith("ID:") || UUID_PATTERN.matcher(t).matches())
                .findFirst()
                .orElse("");
    }
}
