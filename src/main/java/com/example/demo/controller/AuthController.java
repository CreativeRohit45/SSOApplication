package com.example.demo.controller;

import com.example.demo.model.ProtocolType;
import com.example.demo.model.Role;
import com.example.demo.model.SsoConfiguration; // Ensure this is imported
import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import com.example.demo.service.SsoConfigurationService; // Ensure this is imported
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.security.core.Authentication;
import org.springframework.ui.Model;

import java.util.List;

@Controller
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private SsoConfigurationService ssoConfigurationService;

    @GetMapping("/home")
    public String homePage(Model model, Authentication authentication) { // <-- Add parameters

        if (authentication != null && authentication.isAuthenticated()) {
            String email = authentication.getName(); // This works for all login types

            // Find the user in your database (who was just provisioned by your success handler)
            User user = userRepository.findByEmail(email).orElse(null);

            if (user != null) {
                // Add the display name from your database to the model
                model.addAttribute("displayName", user.getDisplayName());
                logger.debug("Added displayName '{}' to model for user '{}'", user.getDisplayName(), email);
            } else {
                // Fallback just in case
                model.addAttribute("displayName", email);
                logger.warn("Could not find user in database for email: {}. Using email as display name.", email);
            }
        }

        return "home";
    }

    @GetMapping("/login")
    public String loginPage(Model model) {
        logger.debug("Accessing login page");
        // Fetch enabled SSO configurations
        List<SsoConfiguration> enabledConfigs = ssoConfigurationService.findAllEnabled();
        logger.debug("Found {} enabled SSO configurations", enabledConfigs.size());

        // Set boolean flags for the view based on protocol type
        // Ensure getProtocolType() method exists and returns ProtocolType enum
        boolean isOidcEnabled = enabledConfigs.stream()
                .anyMatch(config -> config.getProtocolType() == ProtocolType.OIDC);
        boolean isJwtEnabled = enabledConfigs.stream()
                .anyMatch(config -> config.getProtocolType() == ProtocolType.JWT);
        boolean isSamlEnabled = enabledConfigs.stream()
                .anyMatch(config -> config.getProtocolType() == ProtocolType.SAML);

        model.addAttribute("isOidcEnabled", isOidcEnabled);
        model.addAttribute("isJwtEnabled", isJwtEnabled);
        model.addAttribute("isSamlEnabled", isSamlEnabled);

        logger.debug("Login page flags - OIDC: {}, JWT: {}, SAML: {}", isOidcEnabled, isJwtEnabled);

        return "login"; // Renders login.html
    }

    @GetMapping("/register")
    public String registerPage(Model model) {
        model.addAttribute("user", new User());
        return "register";
    }

    @PostMapping("/register")
    public String registerUser(@ModelAttribute User user,
                               @RequestParam("confirmPassword") String confirmPassword,
                               Model model) {

        if (!user.getPassword().equals(confirmPassword)) {

            model.addAttribute("error", "Passwords do not match");

            model.addAttribute("user", user);
            return "register";
        }

        if (userRepository.findByEmail(user.getEmail()).isPresent()) {
            model.addAttribute("error", "Email is already in use");
            model.addAttribute("user", user);
            return "register";
        }

        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRole(Role.USER);

        userRepository.save(user);

        return "redirect:/login";
    }
}