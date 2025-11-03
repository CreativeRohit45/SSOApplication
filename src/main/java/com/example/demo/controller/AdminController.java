package com.example.demo.controller;

import com.example.demo.model.ProtocolType; // Import
import com.example.demo.model.Role;
import com.example.demo.model.SsoConfiguration; // Import
import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import com.example.demo.service.SsoConfigurationService; // Import
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.context.request.WebRequest; // Import
import com.example.demo.config.TenantContext;
import com.example.demo.model.Tenant;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/admin") // Base path for all admin actions
public class AdminController {

    private static final Logger logger = LoggerFactory.getLogger(AdminController.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private SsoConfigurationService ssoConfigurationService;

    /**
     * Shows the main admin dashboard, loading ALL data for all tabs and modals.
     */
    @GetMapping // Maps to GET /admin
    public String adminDashboard(Model model, @AuthenticationPrincipal UserDetails currentUserDetails) {
        logger.debug("Accessing admin dashboard (User Management)");

        Tenant tenant = TenantContext.getCurrentTenant();
        if (tenant == null) {
            // This is a Super Admin, but they're on the wrong page.
            // Or, it's an error. Redirect to super admin login or dashboard.
            return "redirect:/login"; // Or "/super-admin"
        }
        // 1. Get current user's email
        String currentUsername = currentUserDetails.getUsername();

        // 2. Get all users EXCEPT the currently logged-in admin
        List<User> users = userRepository.findByTenantAndRole(tenant, Role.END_USER);
        model.addAttribute("users", users);

        // 3. Add roles for the modal dropdowns
        model.addAttribute("allRoles", new Role[]{Role.END_USER});

        // 4. Add empty user object for the "Create User" modal
        model.addAttribute("newUser", new User()); // 'newUser' must match th:object in create modal

        // 5. Load ALL SSO configs for the tabs
        model.addAttribute("oauthConfig",
                ssoConfigurationService.findByProtocolTypeOrCreate(ProtocolType.OIDC));
        model.addAttribute("jwtConfig",
                ssoConfigurationService.findByProtocolTypeOrCreate(ProtocolType.JWT));
        model.addAttribute("samlConfig",
                ssoConfigurationService.findByProtocolTypeOrCreate(ProtocolType.SAML));

        return "admin"; // Renders admin.html
    }

    // --- SSO Configuration Pages ---
    // These mappings are NO LONGER NEEDED because all forms are on the /admin page
    /*
    @GetMapping("/configure-oauth")
    @GetMapping("/configure-jwt")
    @GetMapping("/configure-saml")
    */

    // --- Save Endpoints ---
    @PostMapping("/save-oauth")
    public String saveOauthConfig(@ModelAttribute("oauthConfig") SsoConfiguration config, WebRequest webRequest, RedirectAttributes redirectAttributes) {
        boolean isEnabled = webRequest.getParameter("enabled") != null;
        config.setEnabled(isEnabled);
        config.setProtocolType(ProtocolType.OIDC);
        // Tenant is set inside the service, so just call save ONCE.
        ssoConfigurationService.save(config);
        redirectAttributes.addFlashAttribute("successMessage", "OAuth/OIDC configuration saved successfully.");
        return "redirect:/admin#oauth";
    }

    @PostMapping("/save-jwt")
    public String saveJwtConfig(@ModelAttribute("jwtConfig") SsoConfiguration config, WebRequest webRequest, RedirectAttributes redirectAttributes) {
        boolean isEnabled = webRequest.getParameter("enabled") != null;
        config.setProtocolType(ProtocolType.JWT);
        // Tenant is set inside the service
        ssoConfigurationService.save(config);
        redirectAttributes.addFlashAttribute("successMessage", "JWT configuration saved successfully.");
        return "redirect:/admin#jwt";
    }

    @PostMapping("/save-saml")
    public String saveSamlConfig(@ModelAttribute("samlConfig") SsoConfiguration config, WebRequest webRequest, RedirectAttributes redirectAttributes) {
        boolean isEnabled = webRequest.getParameter("enabled") != null;
        config.setProtocolType(ProtocolType.SAML);
        // Tenant is set inside the service
        ssoConfigurationService.save(config);
        redirectAttributes.addFlashAttribute("successMessage", "SAML configuration saved successfully.");
        return "redirect:/admin#saml";
    }

    // --- User CRUD Operations ---
    @PostMapping("/users/update")
    public String updateUser(@ModelAttribute User user,
                             @RequestParam(value = "newPassword", required = false) String newPassword,
                             @RequestParam(value = "confirmPassword", required = false) String confirmPassword,
                             RedirectAttributes redirectAttributes) {

        logger.debug("Processing update for user ID: {}", user.getId());
        Optional<User> existingUserOptional = userRepository.findById(user.getId());
        if (existingUserOptional.isEmpty()) {
            redirectAttributes.addFlashAttribute("errorMessage", "User not found.");
            return "redirect:/admin";
        }

        User existingUser = existingUserOptional.get();

        // Password Update Logic
        if (newPassword != null && !newPassword.isBlank()) {
            if (!newPassword.equals(confirmPassword)) {
                redirectAttributes.addFlashAttribute("errorMessage", "Password update failed: Passwords do not match.");
                return "redirect:/admin";
            }
            existingUser.setPassword(passwordEncoder.encode(newPassword));
            logger.info("Password updated for user: {}", existingUser.getEmail());
        }

        // Check for email uniqueness if changed
        if (!existingUser.getEmail().equals(user.getEmail()) && userRepository.findByEmail(user.getEmail()).isPresent()) {
            redirectAttributes.addFlashAttribute("errorMessage", "Cannot update user: Email '" + user.getEmail() + "' is already in use.");
            return "redirect:/admin";
        }

        existingUser.setDisplayName(user.getDisplayName());
        existingUser.setEmail(user.getEmail());
        existingUser.setRole(user.getRole());

        try {
            userRepository.save(existingUser);
            redirectAttributes.addFlashAttribute("successMessage", "User updated successfully.");
        } catch (Exception e) {
            logger.error("Error updating user {}: {}", user.getEmail(), e.getMessage());
            redirectAttributes.addFlashAttribute("errorMessage", "Error updating user: " + e.getMessage());
        }
        return "redirect:/admin";
    }

    @GetMapping("/users/delete/{id}")
    public String deleteUser(@PathVariable("id") Long id,
                             @AuthenticationPrincipal UserDetails currentUserDetails,
                             RedirectAttributes redirectAttributes) {

        logger.debug("Processing delete request for user ID: {}", id);
        // Prevent self-deletion
        Optional<User> userToDeleteOpt = userRepository.findById(id);
        if (userToDeleteOpt.isPresent() && userToDeleteOpt.get().getEmail().equals(currentUserDetails.getUsername())) {
            redirectAttributes.addFlashAttribute("errorMessage", "You cannot delete your own account.");
            return "redirect:/admin";
        }

        if (userToDeleteOpt.isPresent()) {
            try {
                userRepository.deleteById(id);
                redirectAttributes.addFlashAttribute("successMessage", "User deleted successfully.");
            } catch (Exception e) {
                logger.error("Error deleting user {}: {}", id, e.getMessage());
                redirectAttributes.addFlashAttribute("errorMessage", "Error deleting user.");
            }
        } else {
            redirectAttributes.addFlashAttribute("errorMessage", "User not found.");
        }
        return "redirect:/admin";
    }

    // This mapping is for the "Create New User" modal form
    @PostMapping("/users/create")
    public String createUser(@ModelAttribute("newUser") User user, // Bind to "newUser"
                             @RequestParam("confirmPassword") String confirmPassword,
                             RedirectAttributes redirectAttributes) {

        logger.debug("Processing create user request for email: {}", user.getEmail());

        Tenant tenant = TenantContext.getCurrentTenant();
        user.setTenant(tenant);

        // --- FIX: Only one check is needed ---
        if (userRepository.findByEmailAndTenant(user.getEmail(), tenant).isPresent()) {
            redirectAttributes.addFlashAttribute("errorMessage", "Create User Failed: Email is already in use for this tenant.");
            return "redirect:/admin";
        }
        if (!user.getPassword().equals(confirmPassword)) {
            redirectAttributes.addFlashAttribute("errorMessage", "Create User Failed: Passwords do not match.");
            return "redirect:/admin"; // Redirect back
        }

        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRole(Role.END_USER);
        try {
            userRepository.save(user);
            redirectAttributes.addFlashAttribute("successMessage", "User created successfully.");
        } catch (Exception e) {
            logger.error("Error creating user {}: {}", user.getEmail(), e.getMessage());
            redirectAttributes.addFlashAttribute("errorMessage", "Error creating user: " + e.getMessage());
        }
        return "redirect:/admin"; // Back to user list
    }

    // This mapping is now REDUNDANT, but harmless
    @GetMapping("/users/new")
    public String showCreateUserForm(Model model) {
        return "redirect:/admin";
    }
}