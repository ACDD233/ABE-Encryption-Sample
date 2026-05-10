package com.abe.clouddisk.controller;

import com.abe.clouddisk.common.util.JwtUtil;
import com.abe.clouddisk.dto.*;
import com.abe.clouddisk.entity.*;
import com.abe.clouddisk.mapper.*;
import com.abe.clouddisk.service.ABEService;
import com.abe.clouddisk.service.FileService;
import com.abe.clouddisk.service.UserService;
import com.abe.clouddisk.config.SecurityConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import java.util.*;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * REST API tests for the ABEController.
 * This class uses WebMvcTest for lightweight controller testing.
 * All service and mapper dependencies are mocked to isolate the controller logic.
 */
@WebMvcTest(ABEController.class)
@Import(SecurityConfig.class)
public class ABEControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private UserService userService;

    @MockitoBean
    private ABEService abeService;

    @MockitoBean
    private FileService fileService;

    @MockitoBean
    private UserKeyMapper userKeyMapper;

    @MockitoBean
    private UserMapper userMapper;

    @MockitoBean
    private FileMetadataMapper fileMetadataMapper;

    @MockitoBean
    private FileAbeDataMapper fileAbeDataMapper;

    @MockitoBean
    private AttributeCatalogMapper attributeCatalogMapper;

    @MockitoBean
    private SystemKeyMapper systemKeyMapper;

    @MockitoBean
    private JwtUtil jwtUtil;

    private final String testToken = "test.jwt.token";

    /**
     * Initializes common mock behaviors before each test.
     */
    @BeforeEach
    void setUp() {
        when(jwtUtil.getUserIdFromToken(anyString())).thenReturn("1");
    }

    /**
     * Tests successful user login.
     */
    @Test
    public void testLoginSuccess() throws Exception {
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("test@abe.com");
        loginRequest.setPassword("password123");

        Map<String, Object> mockResponse = new HashMap<>();
        mockResponse.put("token", testToken);
        mockResponse.put("username", "testuser");
        mockResponse.put("userId", 1);

        when(userService.login(anyString(), anyString())).thenReturn(mockResponse);

        mockMvc.perform(post("/abe/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value(testToken));
    }

    /**
     * Tests successful user registration.
     */
    @Test
    public void testRegisterSuccess() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setUsername("newuser");
        registerRequest.setEmail("new@abe.com");
        registerRequest.setPassword("password123");

        Map<String, Object> mockResponse = new HashMap<>();
        mockResponse.put("status", "success");
        mockResponse.put("userId", 2);

        when(userService.register(anyString(), anyString(), anyString())).thenReturn(mockResponse);

        mockMvc.perform(post("/abe/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("success"));
    }

    /**
     * Tests file upload and hybrid encryption endpoint.
     */
    @Test
    public void testUploadAndEncrypt() throws Exception {
        User mockUser = new User();
        mockUser.setId(1);
        mockUser.setAttributes("ID:USER-1,Dep:Finance");
        when(userService.getById(anyInt())).thenReturn(mockUser);
        
        ABEService.HybridCiphertext hc = new ABEService.HybridCiphertext();
        hc.aesEncryptedFile = new byte[]{1,2,3};
        hc.iv = new byte[]{4,5,6};
        hc.abeEncryptedKey = new ABEService.ABECiphertext();
        hc.abeEncryptedKey.encryptedSessionKey = new byte[]{7,8,9};
        when(abeService.encryptFileHybrid(any(), any(), any())).thenReturn(hc);

        MockMultipartFile file = new MockMultipartFile("file", "test.txt", "text/plain", "Hello".getBytes());
        MockMultipartFile key = new MockMultipartFile("key", "", "text/plain", Base64.getEncoder().encodeToString("12345678901234567890123456789012".getBytes()).getBytes());
        MockMultipartFile tags = new MockMultipartFile("selectedTags", "", "text/plain", "Dep:Finance".getBytes());
        
        mockMvc.perform(MockMvcRequestBuilders.multipart("/abe/encrypt-file")
                .file(file)
                .file(key)
                .file(tags)
                .header("Authorization", "Bearer " + testToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("success"));
    }

    /**
     * Tests listing of files and directories.
     */
    @Test
    public void testListFiles() throws Exception {
        when(fileService.listFiles(anyInt(), anyInt())).thenReturn(new ArrayList<>());
        mockMvc.perform(get("/abe/list")
                .header("Authorization", "Bearer " + testToken)
                .param("parentId", "0"))
                .andExpect(status().isOk());
    }

    /**
     * Tests directory creation with policy inheritance.
     */
    @Test
    public void testCreateDirectory() throws Exception {
        User mockUser = new User();
        mockUser.setId(1);
        mockUser.setAttributes("ID:USER-1");
        when(userService.getById(anyInt())).thenReturn(mockUser);
        when(fileService.createDirectory(anyString(), anyInt(), anyString(), anyInt())).thenReturn(10);

        mockMvc.perform(post("/abe/mkdir")
                .header("Authorization", "Bearer " + testToken)
                .param("name", "newdir")
                .param("parentId", "0"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(10));
    }

    /**
     * Tests deleting a file or directory.
     */
    @Test
    public void testDeleteItem() throws Exception {
        doNothing().when(fileService).deleteItem(anyInt(), anyInt());
        mockMvc.perform(delete("/abe/delete/1")
                .header("Authorization", "Bearer " + testToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("success"));
    }

    /**
     * Tests moving an item to a different parent directory.
     */
    @Test
    public void testMoveItem() throws Exception {
        doNothing().when(fileService).moveItem(anyInt(), anyInt(), anyInt());
        mockMvc.perform(post("/abe/move")
                .header("Authorization", "Bearer " + testToken)
                .param("id", "1")
                .param("targetParentId", "2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("success"));
    }

    /**
     * Tests copying an item to a different parent directory.
     */
    @Test
    public void testCopyItem() throws Exception {
        doNothing().when(fileService).copyItem(anyInt(), anyInt(), anyInt());
        mockMvc.perform(post("/abe/copy")
                .header("Authorization", "Bearer " + testToken)
                .param("id", "1")
                .param("targetParentId", "2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("success"));
    }

    /**
     * Tests renaming a file or directory.
     */
    @Test
    public void testRenameItem() throws Exception {
        RenameRequest req = new RenameRequest();
        req.setFileId(1);
        req.setNewName("newname.txt");
        doNothing().when(fileService).renameItem(anyInt(), anyString(), anyInt());
        
        mockMvc.perform(post("/abe/rename")
                .header("Authorization", "Bearer " + testToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("success"));
    }

    /**
     * Tests sharing a file by updating its ABE policy.
     */
    @Test
    public void testShareFile() throws Exception {
        ShareRequest req = new ShareRequest();
        req.setFileId(1);
        req.setTargetPolicy("Dep:Finance");
        
        AttributeCatalog attr = new AttributeCatalog();
        attr.setName("Dep:Finance");
        when(userService.listAttributeCatalog()).thenReturn(Collections.singletonList(attr));
        doNothing().when(fileService).shareFile(anyInt(), anyString(), anyInt());

        mockMvc.perform(post("/abe/share")
                .header("Authorization", "Bearer " + testToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("success"));
    }

    /**
     * Tests manual policy update for a file.
     */
    @Test
    public void testUpdatePolicy() throws Exception {
        UpdatePolicyRequest req = new UpdatePolicyRequest();
        req.setId(1);
        req.setSelectedTags("Dep:Finance");
        
        User mockUser = new User();
        mockUser.setAttributes("ID:USER-1,Dep:Finance");
        when(userService.getById(anyInt())).thenReturn(mockUser);
        doNothing().when(fileService).updateItemPolicy(anyInt(), anyString(), anyInt());

        mockMvc.perform(post("/abe/update-policy")
                .header("Authorization", "Bearer " + testToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("success"));
    }

    /**
     * Tests retrieving the system-wide attribute catalog.
     */
    @Test
    public void testListAttributes() throws Exception {
        when(userService.listAttributeCatalog()).thenReturn(new ArrayList<>());
        mockMvc.perform(get("/abe/attributes")
                .header("Authorization", "Bearer " + testToken))
                .andExpect(status().isOk());
    }

    /**
     * Tests retrieving the currently logged-in user's ABE attributes.
     */
    @Test
    public void testGetMyAttributes() throws Exception {
        User mockUser = new User();
        mockUser.setId(1);
        mockUser.setAttributes("ID:USER-1,Dep:Finance");
        when(userService.getById(anyInt())).thenReturn(mockUser);

        mockMvc.perform(get("/abe/my-attributes")
                .header("Authorization", "Bearer " + testToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value(1))
                .andExpect(jsonPath("$.attributes").value("ID:USER-1,Dep:Finance"));
    }

    /**
     * Admin Test: Tests listing all registered users.
     */
    @Test
    public void testListAllUsers() throws Exception {
        when(userService.listAllUsers(anyInt())).thenReturn(new ArrayList<>());
        mockMvc.perform(get("/abe/admin/users")
                .header("Authorization", "Bearer " + testToken))
                .andExpect(status().isOk());
    }

    /**
     * Admin Test: Tests deleting a user.
     */
    @Test
    public void testDeleteUser() throws Exception {
        doNothing().when(userService).deleteUser(anyInt(), anyInt());
        mockMvc.perform(delete("/abe/admin/users/2")
                .header("Authorization", "Bearer " + testToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("success"));
    }

    /**
     * Admin Test: Tests promoting a user to sub-admin.
     */
    @Test
    public void testCreateSubAdmin() throws Exception {
        RegisterRequest req = new RegisterRequest();
        req.setUsername("subadmin");
        req.setEmail("sub@abe.com");
        req.setPassword("pass123");
        when(userService.createSubAdmin(anyString(), anyString(), anyString(), anyInt())).thenReturn(null);

        mockMvc.perform(post("/abe/admin/subadmin")
                .header("Authorization", "Bearer " + testToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("success"));
    }

    /**
     * Admin Test: Tests assigning ABE attributes to a specific user.
     */
    @Test
    public void testAssignAttributes() throws Exception {
        AssignAttributesRequest req = new AssignAttributesRequest();
        req.setTargetUserId(2);
        req.setAttributes("Dep:HR");
        doNothing().when(userService).assignAttributes(anyInt(), anyString(), anyInt());

        mockMvc.perform(post("/abe/admin/assign-attributes")
                .header("Authorization", "Bearer " + testToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("success"));
    }

    /**
     * Admin Test: Tests adding a new attribute to the system catalog.
     */
    @Test
    public void testAddAttribute() throws Exception {
        AttributeRequest req = new AttributeRequest();
        req.setName("Dep:HR");
        req.setDescription("HR Dept");
        doNothing().when(userService).addAttributeToCatalog(anyString(), anyString(), anyInt());

        mockMvc.perform(post("/abe/admin/attributes")
                .header("Authorization", "Bearer " + testToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("success"));
    }

    /**
     * Admin Test: Tests removing an attribute from the system catalog.
     */
    @Test
    public void testDeleteAttribute() throws Exception {
        doNothing().when(userService).deleteAttributeFromCatalog(anyInt(), anyInt());
        mockMvc.perform(delete("/abe/admin/attributes/1")
                .header("Authorization", "Bearer " + testToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("success"));
    }

    /**
     * Tests the full file download and decryption flow (Mocked).
     */
    @Test
    public void testDownloadFile() throws Exception {
        FileMetadata fm = new FileMetadata();
        fm.setIsDir(false);
        fm.setFilePath("pom.xml"); 
        fm.setFilename("downloaded.xml");
        fm.setAesIv(new byte[]{1,2,3});
        
        FileAbeData abe = new FileAbeData();
        abe.setEncryptedSessionKey(new byte[]{4,5,6});
        abe.setCtC(new byte[]{1});
        abe.setCtCPrime(new byte[]{1});
        
        Map<String, Object> data = new HashMap<>();
        data.put("file", fm);
        data.put("abeData", abe);
        
        when(fileService.getFileAndAbeData(anyInt())).thenReturn(data);
        
        User mockUser = new User();
        mockUser.setId(1);
        mockUser.setAttributes("ID:USER-1");
        when(userService.getById(anyInt())).thenReturn(mockUser);
        
        UserKey uk = new UserKey();
        uk.setSkD(new byte[]{1});
        uk.setSkDr(new byte[]{1});
        when(userKeyMapper.selectById(anyInt())).thenReturn(uk);
        
        when(abeService.decryptSessionKey(any(), any())).thenReturn(new byte[]{1,2,3});
        when(abeService.decryptAES(any(), any(), any())).thenReturn("decrypted".getBytes());
        
        mockMvc.perform(get("/abe/download/1")
                .header("Authorization", "Bearer " + testToken))
                .andExpect(status().isOk());
    }
}
