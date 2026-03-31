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
        // For directories, we set dummy filePath and aesIv (or null)
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

        // ABE Filtering: Only return items where policy is satisfied by the user
        return allItems.stream()
                .filter(item -> abeService.isPolicySatisfied(item.getPolicy(), userAttributes))
                .collect(Collectors.toList());
    }

    @Override
    @Transactional
    public void deleteItem(Integer id, Integer userId) {
        FileMetadata item = fileMetadataMapper.selectById(id);
        if (item == null) return;

        // Security Check: Only the owner can delete
        if (!item.getOwnerId().equals(userId)) {
            throw new RuntimeException("Unauthorized: You are not the owner of this file/folder.");
        }

        if (Boolean.TRUE.equals(item.getIsDir())) {
            // Find children
            QueryWrapper<FileMetadata> queryWrapper = new QueryWrapper<>();
            queryWrapper.eq("parent_id", id);
            List<FileMetadata> children = fileMetadataMapper.selectList(queryWrapper);
            
            // Delete all children recursively
            for (FileMetadata child : children) {
                deleteItem(child.getId(), userId);
            }
        } else {
            // Delete actual file from disk
            try {
                if (item.getFilePath() != null && !item.getFilePath().isEmpty()) {
                    Files.deleteIfExists(Paths.get(item.getFilePath()));
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        
        // Delete from database
        fileMetadataMapper.deleteById(id);
    }
}
