package com.example.federated_authorization_server.config;

import com.example.federated_authorization_server.security.CustomSecurityFilter;
import com.example.federated_authorization_server.security.SecurityContext;
import com.example.federated_authorization_server.pojo.User;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfig {

    @Bean
    public User server(){
        return new User();
    }

    @Bean
    public SecurityContext securityContext(User user){
        return new SecurityContext(user);
    }

    @Bean
    public FilterRegistrationBean<CustomSecurityFilter> apiKeySecurityFilterFilter(SecurityContext securityContext){
        FilterRegistrationBean<CustomSecurityFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new CustomSecurityFilter(securityContext));
        registration.addUrlPatterns("/oauth2/*");
        registration.setOrder(0);
        return registration;
    }
}
