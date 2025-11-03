package com.example.demo.controller;

import com.example.demo.model.Role;
import com.example.demo.model.Tenant;
import com.example.demo.model.User;
import com.example.demo.repository.TenantRepository;
import com.example.demo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequestMapping("/super-admin")
public class SuperAdminController {

    @Autowired private TenantRepository tenantRepository;
    @Autowired private UserRepository userRepository;
    @Autowired private PasswordEncoder passwordEncoder;

    @GetMapping
    public String dashboard(Model model) {
        model.addAttribute("tenants", tenantRepository.findAll());
        // This query fulfills "only Customer_Admin should be visible"
        model.addAttribute("customerAdmins", userRepository.findByRole(Role.CUSTOMER_ADMIN));
        return "super-admin-dashboard"; // You must create this HTML page
    }

    @PostMapping("/create-tenant")
    public String createTenant(//@RequestParam String companyName, // Removed
                               @RequestParam String subdomain,
                               @RequestParam String adminEmail,
                               @RequestParam String adminPassword) {

        // 1. Create the Tenant
        Tenant tenant = new Tenant();
        tenant.setSubdomain(subdomain);
        // You can add back a companyName field if you want
        tenantRepository.save(tenant);

        // 2. Create the Customer Admin for this tenant
        User customerAdmin = new User();
        customerAdmin.setEmail(adminEmail);

        // --- FIX: Use subdomain since companyName was removed ---
        customerAdmin.setDisplayName(subdomain + " Admin");
        customerAdmin.setPassword(passwordEncoder.encode(adminPassword));

        // --- SET NEW ROLE ---
        customerAdmin.setRole(Role.CUSTOMER_ADMIN);
        customerAdmin.setTenant(tenant); // Link to the new tenant
        userRepository.save(customerAdmin);

        return "redirect:/super-admin";
    }
}