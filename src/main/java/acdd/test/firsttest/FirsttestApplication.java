package acdd.test.firsttest;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan("acdd.test.firsttest.mapper")
public class FirsttestApplication {

    public static void main(String[] args) {
        SpringApplication.run(FirsttestApplication.class, args);
    }

}
