package acdd.test.firsttest.service;

import acdd.test.firsttest.entity.FileMetadata;
import acdd.test.firsttest.entity.FileAbeData;
import java.util.List;
import java.util.Map;

public interface FileService {
    void saveFileMetadata(FileMetadata fileMetadata, FileAbeData abeData);
    Map<String, Object> getFileAndAbeData(Integer fileId);
    
    // New methods for directory support
    void createDirectory(String name, Integer parentId, String policy, Integer ownerId);
    List<FileMetadata> listFiles(Integer parentId, Integer userId);
    
    // Delete file or directory
    void deleteItem(Integer id, Integer userId);

    // Move and Copy
    void moveItem(Integer id, Integer targetParentId, Integer userId);
    void copyItem(Integer id, Integer targetParentId, Integer userId);

    // Share
    void shareFile(Integer fileId, String targetPolicy, Integer userId);

    // Update Policy (for folders)
    void updateItemPolicy(Integer id, String newTags, Integer userId);
}
