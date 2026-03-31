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
}
