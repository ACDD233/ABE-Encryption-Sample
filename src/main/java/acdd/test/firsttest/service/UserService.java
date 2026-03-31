package acdd.test.firsttest.service;

import acdd.test.firsttest.entity.User;
import java.util.Map;

public interface UserService {
    Map<String, Object> register(String username, String email, String password);
    Map<String, Object> login(String email, String password);
    User getById(Integer id);
}
