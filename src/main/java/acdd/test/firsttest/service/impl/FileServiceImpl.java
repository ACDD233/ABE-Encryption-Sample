package acdd.test.firsttest.service.impl;

import acdd.test.firsttest.entity.FileAbeData;
import acdd.test.firsttest.entity.FileMetadata;
import acdd.test.firsttest.mapper.FileAbeDataMapper;
import acdd.test.firsttest.mapper.FileMetadataMapper;
import acdd.test.firsttest.service.FileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.Map;

@Service
public class FileServiceImpl implements FileService {

    @Autowired
    private FileMetadataMapper fileMetadataMapper;

    @Autowired
    private FileAbeDataMapper fileAbeDataMapper;

    @Override
    @Transactional
    public void saveFileMetadata(FileMetadata fileMetadata, FileAbeData abeData) {
        fileMetadataMapper.insert(fileMetadata);
        abeData.setFileId(fileMetadata.getId());
        fileAbeDataMapper.insert(abeData);
    }

    @Override
    public Map<String, Object> getFileAndAbeData(Integer fileId) {
        FileMetadata file = fileMetadataMapper.selectById(fileId);
        FileAbeData abeData = fileAbeDataMapper.selectById(fileId);
        
        if (file == null || abeData == null) return null;

        Map<String, Object> result = new HashMap<>();
        result.put("file", file);
        result.put("abeData", abeData);
        return result;
    }
}
