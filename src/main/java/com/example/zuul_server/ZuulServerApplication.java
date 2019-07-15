package com.example.zuul_server;


import com.example.zuul_server.models.Role;
import com.example.zuul_server.repositories.RoleRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
@EnableEurekaClient
@EnableZuulProxy
public class ZuulServerApplication {
    @Bean
    CommandLineRunner init(RoleRepository roleRepository) {

        return args -> {

            Role adminRole = roleRepository.findByRole("ADMIN");
            if (adminRole == null) {
                Role newAdminRole = new Role();
                newAdminRole.setRole("ADMIN");
                roleRepository.save(newAdminRole);
            }
            Role usernRole = roleRepository.findByRole("USER");
            if (usernRole == null) {
                Role newAdminRole = new Role();
                newAdminRole.setRole("USER");
                roleRepository.save(newAdminRole);
            }
        };

    }


    public static void main(String[] args) {
        SpringApplication.run(ZuulServerApplication.class, args);
    }

}
