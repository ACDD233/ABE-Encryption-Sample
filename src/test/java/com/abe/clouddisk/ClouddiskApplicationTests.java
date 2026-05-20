/*
 * Copyright (C) 2026 ACDD233
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
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
