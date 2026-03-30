package acdd.test.firsttest.service;

import acdd.test.firsttest.entity.FileMetadata;
import acdd.test.firsttest.entity.FileAbeData;
import java.util.Map;

public interface FileService {
    void saveFileMetadata(FileMetadata fileMetadata, FileAbeData abeData);
    Map<String, Object> getFileAndAbeData(Integer fileId);
}
