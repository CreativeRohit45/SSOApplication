package com.example.demo.controller;

import com.example.demo.model.ProtocolType; // Import ProtocolType
import com.example.demo.model.Role;
import com.example.demo.model.SsoConfiguration; // Import SsoConfiguration
import com.example.demo.model.User;
import com.example.demo.repository.SsoConfigurationRepository; // Import Repository
import com.example.demo.repository.UserRepository;
import com.example.demo.service.SsoConfigurationService; // Import Service
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
import org.springframework.web.context.request.WebRequest;

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
     * Shows the main admin dashboard (User Management).
     */
    @GetMapping // Maps to GET /admin
    public String adminDashboard(Model model) {
        logger.debug("Accessing admin dashboard (User Management)");
        List<User> users = userRepository.findAll();
        model.addAttribute("users", users);
        model.addAttribute("allRoles", Role.values()); // For edit modal
        return "admin"; // Renders admin.html
    }

    // --- SSO Configuration Pages ---

    @GetMapping("/configure-oauth")
    public String showConfigureOauthForm(Model model) {
        logger.debug("Accessing Configure OAuth/OIDC page");
        SsoConfiguration config = ssoConfigurationService.findByProtocolTypeOrCreate(ProtocolType.OIDC);
        // --- ADD LOG ---
        logger.info("Loaded OIDC Config - ID: {}, Enabled: {}", config.getId(), config.isEnabled());
        // -------------
        model.addAttribute("config", config);
        return "config-oauth";
    }

    @GetMapping("/configure-jwt")
    public String showConfigureJwtForm(Model model) {
        logger.debug("Accessing Configure JWT page");
        SsoConfiguration config = ssoConfigurationService.findByProtocolTypeOrCreate(ProtocolType.JWT);
        // --- ADD LOG ---
        logger.info("Loaded JWT Config - ID: {}, Enabled: {}", config.getId(), config.isEnabled());
        // -------------
        model.addAttribute("config", config);
        return "config-jwt";
    }

    @GetMapping("/configure-saml")
    public String showConfigureSamlForm(Model model) {
        logger.debug("Accessing Configure SAML page");
        SsoConfiguration config = ssoConfigurationService.findByProtocolTypeOrCreate(ProtocolType.SAML);
        // --- ADD LOG ---
        logger.info("Loaded SAML Config - ID: {}, Enabled: {}", config.getId(), config.isEnabled());
        // -------------
        model.addAttribute("config", config);
        return "config-saml";
    }

    // --- Placeholder Save Endpoints ---
    // TODO: Implement saving logic for each configuration type

    @PostMapping("/save-oauth")
    public String saveOauthConfig(@ModelAttribute SsoConfiguration config,
                                  WebRequest webRequest, // Add WebRequest parameter
                                  RedirectAttributes redirectAttributes) {

        // --- Explicitly set 'enabled' based on parameter presence ---
        boolean isEnabled = webRequest.getParameter("enabled") != null;
        config.setEnabled(isEnabled);
        logger.info("Received OAuth/OIDC config save request. 'enabled' checked from request: {}", isEnabled);
        // -----------------------------------------------------------

        try {
            config.setProtocolType(ProtocolType.OIDC);
            ssoConfigurationService.save(config);
            redirectAttributes.addFlashAttribute("successMessage", "OAuth/OIDC configuration saved successfully.");
        } catch (Exception e) {
            logger.error("Error saving OAuth/OIDC config: {}", e.getMessage(), e);
            redirectAttributes.addFlashAttribute("errorMessage", "Error saving OAuth/OIDC configuration: " + e.getMessage());
        }
        return "redirect:/admin/configure-oauth";
    }

    @PostMapping("/save-jwt")
    public String saveJwtConfig(@ModelAttribute SsoConfiguration config,
                                WebRequest webRequest, // Add WebRequest parameter
                                RedirectAttributes redirectAttributes) {

        // --- Explicitly set 'enabled' based on parameter presence ---
        boolean isEnabled = webRequest.getParameter("enabled") != null;
        config.setEnabled(isEnabled);
        logger.info("Received JWT config save request. 'enabled' checked from request: {}", isEnabled);
        // -----------------------------------------------------------

        try {
            config.setProtocolType(ProtocolType.JWT);
            ssoConfigurationService.save(config);
            redirectAttributes.addFlashAttribute("successMessage", "JWT configuration saved successfully.");
        } catch (Exception e) {
            logger.error("Error saving JWT config: {}", e.getMessage(), e);
            redirectAttributes.addFlashAttribute("errorMessage", "Error saving JWT configuration: " + e.getMessage());
        }
        return "redirect:/admin/configure-jwt";
    }

    @PostMapping("/save-saml")
    public String saveSamlConfig(@ModelAttribute SsoConfiguration config,
                                 WebRequest webRequest, // Add WebRequest parameter
                                 RedirectAttributes redirectAttributes) {

        // --- Explicitly set 'enabled' based on parameter presence ---
        boolean isEnabled = webRequest.getParameter("enabled") != null;
        config.setEnabled(isEnabled);
        logger.info("Received SAML config save request. 'enabled' checked from request: {}", isEnabled);
        // -----------------------------------------------------------

        try {
            config.setProtocolType(ProtocolType.SAML);
            ssoConfigurationService.save(config);
            redirectAttributes.addFlashAttribute("successMessage", "SAML configuration saved successfully.");
        } catch (Exception e) {
            logger.error("Error saving SAML config: {}", e.getMessage(), e);
            redirectAttributes.addFlashAttribute("errorMessage", "Error saving SAML configuration: " + e.getMessage());
        }
        return "redirect:/admin/configure-saml";
    }


    // --- User CRUD Operations ---

    @PostMapping("/users/update")
    public String updateUser(@ModelAttribute User user,
                             // --- Add password fields ---
                             @RequestParam(value = "newPassword", required = false) String newPassword,
                             @RequestParam(value = "confirmPassword", required = false) String confirmPassword,
                             RedirectAttributes redirectAttributes) {
        logger.debug("Processing update for user ID: {}", user.getId());

        Optional<User> existingUserOptional = userRepository.findById(user.getId());
        if (existingUserOptional.isEmpty()) {
            logger.warn("Attempted to update non-existent user with ID: {}", user.getId());
            redirectAttributes.addFlashAttribute("errorMessage", "User not found.");
            return "redirect:/admin";
        }

        User existingUser = existingUserOptional.get();

        // --- Password Update Logic ---
        boolean passwordChanged = false;
        if (newPassword != null && !newPassword.isBlank()) {
            if (!newPassword.equals(confirmPassword)) {
                logger.warn("Password update failed for user ID {}: Passwords do not match", user.getId());
                redirectAttributes.addFlashAttribute("errorMessage", "Password update failed: Passwords do not match.");
                // Redirect back to admin page (modal won't automatically reopen with error, this is simpler)
                return "redirect:/admin";
                // Alternative: Redirect back to an edit page if you had one, passing the error
                // return "redirect:/admin/users/edit/" + user.getId() + "?passwordError=true";
            }
            // If passwords match and are not blank, encode and set
            existingUser.setPassword(passwordEncoder.encode(newPassword));
            passwordChanged = true;
            logger.info("Password updated for user: {}", existingUser.getEmail());
        } // else: no new password provided, keep the old one

        // --- Update other fields ---
        existingUser.setDisplayName(user.getDisplayName());
        // Basic check to prevent duplicate emails if email is changed
        if (!existingUser.getEmail().equals(user.getEmail()) && userRepository.findByEmail(user.getEmail()).isPresent()) {
            logger.warn("Attempted to update email for user {} to an already existing email: {}", existingUser.getEmail(), user.getEmail());
            redirectAttributes.addFlashAttribute("errorMessage", "Cannot update user: Email '" + user.getEmail() + "' is already in use.");
            return "redirect:/admin";
        }
        existingUser.setEmail(user.getEmail());
        existingUser.setRole(user.getRole());


        try {
            userRepository.save(existingUser);
            logger.info("Updated user: {}", existingUser.getEmail());
            String successMsg = "User updated successfully.";
            if (passwordChanged) {
                successMsg += " Password was changed.";
            }
            redirectAttributes.addFlashAttribute("successMessage", successMsg);
        } catch (Exception e) {
            logger.error("Error updating user {}: {}", user.getEmail(), e.getMessage());
            redirectAttributes.addFlashAttribute("errorMessage", "Error updating user: " + e.getMessage());
        }

        return "redirect:/admin"; // Back to user list
    }

    @GetMapping("/users/delete/{id}")
    public String deleteUser(@PathVariable("id") Long id, RedirectAttributes redirectAttributes) {
        logger.debug("Processing delete request for user ID: {}", id);
        if (userRepository.existsById(id)) {
            try {
                userRepository.deleteById(id);
                logger.info("Deleted user with ID: {}", id);
                redirectAttributes.addFlashAttribute("successMessage", "User deleted successfully.");
            } catch (Exception e) {
                logger.error("Error deleting user {}: {}", id, e.getMessage());
                redirectAttributes.addFlashAttribute("errorMessage", "Error deleting user.");
            }
        } else {
            logger.warn("Attempted to delete non-existent user with ID: {}", id);
            redirectAttributes.addFlashAttribute("errorMessage", "User not found.");
        }
        return "redirect:/admin"; // Back to user list
    }

    @GetMapping("/users/new")
    public String showCreateUserForm(Model model) {
        logger.debug("Displaying create new user form");
        model.addAttribute("user", new User());
        model.addAttribute("allRoles", Role.values());
        return "user-new"; // Assumes user-new.html exists
    }

    @PostMapping("/users/create")
    public String createUser(@ModelAttribute User user,
                             @RequestParam("confirmPassword") String confirmPassword,
                             RedirectAttributes redirectAttributes,
                             Model model) {
        logger.debug("Processing create user request for email: {}", user.getEmail());
        // Validation
        if (!user.getPassword().equals(confirmPassword)) {
            model.addAttribute("error", "Passwords do not match");
            model.addAttribute("user", user);
            model.addAttribute("allRoles", Role.values());
            return "user-new";
        }
        if (userRepository.findByEmail(user.getEmail()).isPresent()) {
            model.addAttribute("error", "Email is already in use");
            model.addAttribute("user", user);
            model.addAttribute("allRoles", Role.values());
            return "user-new";
        }

        // Process Creation
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        // Role is set from form

        try {
            userRepository.save(user);
            logger.info("Admin created new user: {}", user.getEmail());
            redirectAttributes.addFlashAttribute("successMessage", "User created successfully.");
            return "redirect:/admin";
        } catch (Exception e) {
            logger.error("Error creating user {}: {}", user.getEmail(), e.getMessage());
            model.addAttribute("error", "Error creating user: " + e.getMessage());
            model.addAttribute("user", user);
            model.addAttribute("allRoles", Role.values());
            return "user-new";
        }
    }
}

