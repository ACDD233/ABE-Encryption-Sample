package com.abe.clouddisk;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Basic smoke test to ensure that the Spring Application Context loads correctly.
 */
@SpringBootTest
@org.springframework.test.context.ActiveProfiles("test")
class ClouddiskApplicationTests {

    /**
     * Verifies that the application context starts without any bean creation or dependency injection issues.
     */
    @Test
    void contextLoads() {
    }

}
