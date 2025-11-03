package com.example.demo.config;

import com.example.demo.model.Role;
import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DataSeeder implements CommandLineRunner {

    private static final Logger logger = LoggerFactory.getLogger(DataSeeder.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        // Check if a SUPER_ADMIN already exists
        if (userRepository.findByRole(Role.SUPER_ADMIN).isEmpty()) {
            logger.info("No SUPER_ADMIN found, creating default super admin...");

            User superAdmin = new User();
            superAdmin.setEmail("super@admin.com");
            superAdmin.setPassword(passwordEncoder.encode("admin")); // Password is "admin"
            superAdmin.setDisplayName("Super Admin");
            superAdmin.setRole(Role.SUPER_ADMIN);
            superAdmin.setTenant(null); // Super admin has no tenant

            userRepository.save(superAdmin);
            logger.info("SUPER_ADMIN created with email: super@admin.com");
        } else {
            logger.info("SUPER_ADMIN user already exists.");
        }
    }
}