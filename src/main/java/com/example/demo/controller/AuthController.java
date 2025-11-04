package com.example.demo.controller;

import com.example.demo.config.TenantContext;
import com.example.demo.model.*;
import com.example.demo.repository.UserRepository;
import com.example.demo.service.SsoConfigurationService;
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
    public String homePage(Model model, Authentication authentication) {

        if (authentication != null && authentication.isAuthenticated()) {
            String email = authentication.getName();

            // --- THIS IS THE FIX ---
            Tenant tenant = TenantContext.getCurrentTenant();
            User user = null;

            if (tenant != null) {
                // Find the user *within their tenant*
                user = userRepository.findByEmailAndTenant(email, tenant).orElse(null);
            } else if (authentication.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_SUPER_ADMIN"))) {
                // Or, if they are a super admin, find them with a null tenant
                user = userRepository.findByEmailAndTenantIsNull(email).orElse(null);
            }
            // --- END FIX ---


            if (user != null) {
                model.addAttribute("displayName", user.getDisplayName());
                logger.debug("Added displayName '{}' to model for user '{}'", user.getDisplayName(), email);
            } else {
                model.addAttribute("displayName", email);
                logger.warn("Could not find user in database for email: {}. Using email as display name.", email);
            }
        }

        return "home";
    }

    @GetMapping("/oauth-test-results")
    public String showOidcTestResults() {
        return "oauth-test-results";
    }

    @GetMapping("/login")
    public String loginPage(Model model) {
        logger.debug("Accessing login page");
        List<SsoConfiguration> enabledConfigs = ssoConfigurationService.findAllEnabled();
        logger.debug("Found {} enabled SSO configurations", enabledConfigs.size());

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

        return "login";
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

        Tenant tenant = TenantContext.getCurrentTenant();
        if (tenant == null) {
            model.addAttribute("error", "Registration is not allowed on this domain.");
            model.addAttribute("user", user);
            return "register";
        }

        if (!user.getPassword().equals(confirmPassword)) {
            model.addAttribute("error", "Passwords do not match");
            model.addAttribute("user", user);
            return "register";
        }

        if (userRepository.findByEmailAndTenant(user.getEmail(), tenant).isPresent()) {
            model.addAttribute("error", "Email is already in use for this account.");
            model.addAttribute("user", user);
            return "register";
        }

        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRole(Role.END_USER);
        user.setTenant(tenant);

        userRepository.save(user);

        return "redirect:/login";
    }
}
