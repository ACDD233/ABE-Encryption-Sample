package acdd.test.firsttest.service;

import acdd.test.firsttest.entity.User;
import java.util.Map;

public interface UserService {
    Map<String, Object> register(String username, String email, String password);
    Map<String, Object> login(String email, String password);
    User getById(Integer id);
    
    // Admin management
    void assignAttributes(Integer userId, String attributes, Integer adminId) throws Exception;
    java.util.List<User> listAllUsers(Integer adminId) throws Exception;

    // Attribute Catalog Management
    void addAttributeToCatalog(String name, String description, Integer adminId) throws Exception;
    void deleteAttributeFromCatalog(Integer attributeId, Integer adminId) throws Exception;
    java.util.List<acdd.test.firsttest.entity.AttributeCatalog> listAttributeCatalog();
}
