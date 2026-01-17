package acdd.test.firsttest;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;

@SpringBootApplication(exclude = {DataSourceAutoConfiguration.class})
public class FirsttestApplication {

    public static void main(String[] args) {
        SpringApplication.run(FirsttestApplication.class, args);
    }

}
