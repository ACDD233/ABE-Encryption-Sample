package com.abe.clouddisk.service;

import com.abe.clouddisk.entity.FileMetadata;
import com.abe.clouddisk.entity.FileAbeData;
import java.util.List;
import java.util.Map;

/**
 * Service interface for file management and metadata operations.
 * Handles file persistence, directory structures, and ABE-related metadata.
 */
public interface FileService {
    
    /**
     * Saves file metadata and its associated ABE encryption data to the database.
     *
     * @param fileMetadata The metadata of the file (name, path, owner, etc.).
     * @param abeData      The ABE ciphertext components and encrypted session key.
     */
    void saveFileMetadata(FileMetadata fileMetadata, FileAbeData abeData);

    /**
     * Retrieves file metadata and ABE data for a specific file ID.
     *
     * @param fileId The ID of the file to retrieve.
     * @return A map containing "file" (FileMetadata) and "abeData" (FileAbeData).
     */
    Map<String, Object> getFileAndAbeData(Integer fileId);
    
    /**
     * Creates a new directory entry in the database.
     *
     * @param name     The name of the directory.
     * @param parentId The ID of the parent directory.
     * @param policy   The ABE access policy for the directory.
     * @param ownerId  The ID of the user who owns the directory.
     * @return The ID of the newly created directory.
     */
    Integer createDirectory(String name, Integer parentId, String policy, Integer ownerId);

    /**
     * Lists files and directories within a specified parent directory for a given user.
     *
     * @param parentId The ID of the parent directory.
     * @param userId   The ID of the user requesting the list.
     * @return A list of FileMetadata objects.
     */
    List<FileMetadata> listFiles(Integer parentId, Integer userId);
    
    /**
     * Deletes a file or directory. If it's a directory, all its contents are recursively deleted.
     *
     * @param id     The ID of the item to delete.
     * @param userId The ID of the user performing the deletion.
     */
    void deleteItem(Integer id, Integer userId);

    /**
     * Deletes all files and directories owned by a specific user.
     *
     * @param userId The ID of the user whose files should be deleted.
     */
    void deleteUserFiles(Integer userId);

    /**
     * Moves a file or directory to a new parent directory.
     *
     * @param id             The ID of the item to move.
     * @param targetParentId The ID of the target parent directory.
     * @param userId         The ID of the user performing the move.
     */
    void moveItem(Integer id, Integer targetParentId, Integer userId);

    /**
     * Copies a file or directory to a new parent directory.
     *
     * @param id             The ID of the item to copy.
     * @param targetParentId The ID of the target parent directory.
     * @param userId         The ID of the user performing the copy.
     */
    void copyItem(Integer id, Integer targetParentId, Integer userId);

    /**
     * Shares a file by updating its ABE access policy.
     *
     * @param fileId       The ID of the file to share.
     * @param targetPolicy The new ABE access policy for the file.
     * @param userId       The ID of the user performing the share.
     */
    void shareFile(Integer fileId, String targetPolicy, Integer userId);

    /**
     * Updates the access policy of an item (file or directory).
     *
     * @param id      The ID of the item.
     * @param newTags The new comma-separated tags for the policy.
     * @param userId  The ID of the user performing the update.
     */
    void updateItemPolicy(Integer id, String newTags, Integer userId);

    /**
     * Renames a file or directory.
     *
     * @param id      The ID of the item to rename.
     * @param newName The new name for the item.
     * @param userId  The ID of the user performing the rename.
     */
    void renameItem(Integer id, String newName, Integer userId);
}
