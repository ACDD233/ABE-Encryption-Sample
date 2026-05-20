package com.abe.clouddisk.service;

import com.abe.clouddisk.entity.User;
import com.abe.clouddisk.entity.AttributeCatalog;
import java.util.Map;
import java.util.List;

/**
 * Service interface for user management and authentication.
 * Handles user lifecycle, attribute assignment, and administrative tasks.
 */
public interface UserService {
    
    /**
     * Registers a new user in the system, generating their ABE secret keys and an identity attribute.
     *
     * @param username The username of the new user.
     * @param email    The email address of the new user.
     * @param password The raw password of the new user.
     * @return A map containing registration details or status.
     */
    Map<String, Object> register(String username, String email, String password);

    /**
     * Authenticates a user and generates a JWT token upon successful login.
     *
     * @param email    The user's email address.
     * @param password The user's raw password.
     * @return A map containing the JWT token and user information.
     */
    Map<String, Object> login(String email, String password);

    /**
     * Retrieves a user entity by its unique ID.
     *
     * @param id The ID of the user.
     * @return The User entity, or null if not found.
     */
    User getById(Integer id);
    
    /**
     * Admin only: Creates a new Sub-Admin in the system.
     *
     * @param username The username of the Sub-Admin.
     * @param email    The email address of the Sub-Admin.
     * @param password The raw password of the Sub-Admin.
     * @param adminId  The ID of the administrator performing the operation.
     * @return A map containing registration details.
     */
    Map<String, Object> createSubAdmin(String username, String email, String password, Integer adminId);

    /**
     * Admin only: Assigns a new set of ABE attributes to a user and regenerates their secret keys.
     *
     * @param userId     The ID of the target user.
     * @param attributes The comma-separated list of attributes to assign.
     * @param adminId    The ID of the administrator performing the operation.
     * @throws Exception If the requester is not an admin or the operation fails.
     */
    void assignAttributes(Integer userId, String attributes, Integer adminId) throws Exception;

    /**
     * Admin only: Lists all users currently registered in the system.
     *
     * @param adminId The ID of the administrator performing the operation.
     * @return A list of all User entities.
     * @throws Exception If the requester is not an admin.
     */
    List<User> listAllUsers(Integer adminId) throws Exception;

    /**
     * Admin only: Deletes a user and all their associated files and keys.
     *
     * @param targetUserId The ID of the user to delete.
     * @param adminId      The ID of the administrator performing the operation.
     */
    void deleteUser(Integer targetUserId, Integer adminId);

    /**
     * Admin only: Adds a new attribute definition to the system attribute catalog.
     *
     * @param name        The name of the attribute.
     * @param description A brief description of the attribute's purpose.
     * @param adminId     The ID of the administrator performing the operation.
     * @throws Exception If the requester is not an admin.
     */
    void addAttributeToCatalog(String name, String description, Integer adminId) throws Exception;

    /**
     * Admin only: Deletes an attribute definition from the catalog.
     *
     * @param attributeId The ID of the attribute to delete.
     * @param adminId     The ID of the administrator performing the operation.
     * @throws Exception If the requester is not an admin.
     */
    void deleteAttributeFromCatalog(Integer attributeId, Integer adminId) throws Exception;

    /**
     * Lists all attribute definitions available in the system catalog.
     *
     * @return A list of AttributeCatalog entities.
     */
    List<AttributeCatalog> listAttributeCatalog();
}
