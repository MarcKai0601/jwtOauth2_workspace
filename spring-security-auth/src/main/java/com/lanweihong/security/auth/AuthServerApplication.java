package com.lanweihong.security.auth;

import com.lanweihong.security.auth.config.Oauth2ServerConfig;
import com.lanweihong.security.auth.config.WebSecurityConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;

/**
 * @author lanweihong
 * @date 2021/1/13 01:28
 */
@SpringBootApplication
@EnableCaching
@EnableResourceServer
@EnableAuthorizationServer
@EnableDiscoveryClient
public class AuthServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthServerApplication.class, args);
    }
}
