package acdd.test.firsttest.service.impl;

import acdd.test.firsttest.entity.FileAbeData;
import acdd.test.firsttest.entity.FileMetadata;
import acdd.test.firsttest.entity.User;
import acdd.test.firsttest.mapper.FileAbeDataMapper;
import acdd.test.firsttest.mapper.FileMetadataMapper;
import acdd.test.firsttest.mapper.UserMapper;
import acdd.test.firsttest.service.ABEService;
import acdd.test.firsttest.service.FileService;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class FileServiceImpl implements FileService {

    @Autowired
    private FileMetadataMapper fileMetadataMapper;

    @Autowired
    private FileAbeDataMapper fileAbeDataMapper;

    @Autowired
    private UserMapper userMapper;

    @Autowired
    private ABEService abeService;

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

    @Override
    public void createDirectory(String name, Integer parentId, String policy, Integer ownerId) {
        FileMetadata dir = new FileMetadata();
        dir.setFilename(name);
        dir.setParentId(parentId == null ? 0 : parentId);
        dir.setPolicy(policy);
        dir.setOwnerId(ownerId);
        dir.setIsDir(true);
        dir.setUploadTime(LocalDateTime.now());
        dir.setFilePath("");
        dir.setAesIv(new byte[16]);
        fileMetadataMapper.insert(dir);
    }

    @Override
    public List<FileMetadata> listFiles(Integer parentId, Integer userId) {
        User user = userMapper.selectById(userId);
        String userAttributes = (user != null) ? user.getAttributes() : "";

        QueryWrapper<FileMetadata> queryWrapper = new QueryWrapper<>();
        queryWrapper.eq("parent_id", parentId == null ? 0 : parentId);

        List<FileMetadata> allItems = fileMetadataMapper.selectList(queryWrapper);

        return allItems.stream()
                .filter(item -> abeService.isPolicySatisfied(item.getPolicy(), userAttributes))
                .collect(Collectors.toList());
    }

    @Override
    @Transactional
    public void deleteItem(Integer id, Integer userId) {
        FileMetadata item = fileMetadataMapper.selectById(id);
        if (item == null) return;

        if (!item.getOwnerId().equals(userId)) {
            throw new RuntimeException("Unauthorized: You are not the owner of this file/folder.");
        }

        if (Boolean.TRUE.equals(item.getIsDir())) {
            QueryWrapper<FileMetadata> queryWrapper = new QueryWrapper<>();
            queryWrapper.eq("parent_id", id);
            List<FileMetadata> children = fileMetadataMapper.selectList(queryWrapper);
            for (FileMetadata child : children) {
                deleteItem(child.getId(), userId);
            }
        } else {
            // Reference counting for physical file deletion
            String filePath = item.getFilePath();
            if (filePath != null && !filePath.isEmpty()) {
                QueryWrapper<FileMetadata> qw = new QueryWrapper<>();
                qw.eq("file_path", filePath);
                Long count = fileMetadataMapper.selectCount(qw);
                // Only delete the physical file if this is the last reference
                if (count != null && count <= 1) {
                    try {
                        Files.deleteIfExists(Paths.get(filePath));
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
        fileMetadataMapper.deleteById(id);
    }

    @Override
    @Transactional
    public void moveItem(Integer id, Integer targetParentId, Integer userId) {
        FileMetadata item = fileMetadataMapper.selectById(id);
        if (item == null || !item.getOwnerId().equals(userId)) {
            throw new RuntimeException("Unauthorized or file not found.");
        }
        item.setParentId(targetParentId);
        fileMetadataMapper.updateById(item);
    }

    @Override
    @Transactional
    public void copyItem(Integer id, Integer targetParentId, Integer userId) {
        FileMetadata item = fileMetadataMapper.selectById(id);
        if (item == null || !item.getOwnerId().equals(userId)) {
            throw new RuntimeException("Unauthorized or file not found.");
        }

        if (Boolean.TRUE.equals(item.getIsDir())) {
            // 1. Create a new directory
            FileMetadata newDir = new FileMetadata();
            newDir.setFilename(item.getFilename() + " (Copy)");
            newDir.setParentId(targetParentId);
            newDir.setPolicy(item.getPolicy());
            newDir.setOwnerId(userId);
            newDir.setIsDir(true);
            newDir.setUploadTime(LocalDateTime.now());
            newDir.setFilePath("");
            newDir.setAesIv(new byte[16]);
            fileMetadataMapper.insert(newDir);

            // 2. Recursively copy all items inside this directory
            QueryWrapper<FileMetadata> queryWrapper = new QueryWrapper<>();
            queryWrapper.eq("parent_id", id);
            List<FileMetadata> children = fileMetadataMapper.selectList(queryWrapper);
            for (FileMetadata child : children) {
                copyItem(child.getId(), newDir.getId(), userId);
            }
        } else {
            // 3. Logic-Only Copy (CoW style): point to same file_path
            FileMetadata newItem = new FileMetadata();
            newItem.setFilename(item.getFilename() + " (Copy)");
            newItem.setParentId(targetParentId);
            newItem.setOwnerId(userId);
            newItem.setFilePath(item.getFilePath()); // Same path! No disk space taken.
            newItem.setAesIv(item.getAesIv());
            newItem.setPolicy(item.getPolicy());
            newItem.setIsDir(false);
            newItem.setUploadTime(LocalDateTime.now());
            fileMetadataMapper.insert(newItem);

            // Also copy ABE data components
            FileAbeData originalAbe = fileAbeDataMapper.selectById(id);
            if (originalAbe != null) {
                FileAbeData newAbe = new FileAbeData();
                newAbe.setFileId(newItem.getId());
                newAbe.setEncryptedSessionKey(originalAbe.getEncryptedSessionKey());
                newAbe.setCtC(originalAbe.getCtC());
                newAbe.setCtCPrime(originalAbe.getCtCPrime());
                fileAbeDataMapper.insert(newAbe);
            }
        }
    }
}
