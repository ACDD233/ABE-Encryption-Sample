package com.abe.clouddisk;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan("com.abe.clouddisk.mapper")
public class ClouddiskApplication {

    public static void main(String[] args) {
        SpringApplication.run(ClouddiskApplication.class, args);
    }

}
