package com.hiringbell.authenticator.model;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@ConfigurationProperties(prefix = "spring.datasource")
@Component
@Data
public class MasterDatabaseManager {

    String driver;
    String url;
    String username;
    String password;
}
