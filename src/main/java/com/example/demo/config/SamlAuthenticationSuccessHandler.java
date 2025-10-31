package com.example.demo.config; // Or your package name

import com.example.demo.model.Role;
import com.example.demo.model.SsoConfiguration;
import com.example.demo.model.User;
import com.example.demo.model.ProtocolType;
import com.example.demo.repository.UserRepository;
import com.example.demo.service.SsoConfigurationService; // Make sure to import this
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Collection;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors; // Import Collectors

@Component
public class SamlAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger logger = LoggerFactory.getLogger(SamlAuthenticationSuccessHandler.class);

    @Autowired
    private UserRepository userRepository;

    @Lazy
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private SsoConfigurationService ssoConfigurationService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        // --- 1. PROVISIONING LOGIC ---

        String email = authentication.getName();
        logger.info("SAML login successful for user: {}", email);

        // Run Just-in-Time provisioning for this SAML user
        provisionSamlUser(authentication, email);


        // --- 2. REDIRECTION LOGIC ---

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

        // Log the authorities
        String roles = authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(", "));
        logger.info("User '{}' (SAML) authenticated with final authorities: {}", email, roles);

        // Redirect based on role
        boolean isAdmin = authorities.stream()
                .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("ROLE_ADMIN"));

        if (isAdmin) {
            logger.info("Redirecting SAML user to /admin");
            response.sendRedirect("/admin/dashboard"); // Or your admin path
        } else {
            logger.info("Redirecting SAML user to /home");
            response.sendRedirect("/home");
        }
    }

    /**
     * Checks if a SAML user exists in the local DB. If not, creates them.
     */
    private void provisionSamlUser(Authentication authentication, String email) {
        Optional<User> userOptional = userRepository.findByEmail(email);

        User user;
        if (userOptional.isEmpty()) {
            logger.info("SAML user {} not found in local database. Provisioning new user.", email);

            user = new User();
            user.setEmail(email);
            user.setPassword(passwordEncoder.encode(UUID.randomUUID().toString()));
            user.setRole(Role.USER); // Default role

            if (authentication.getPrincipal() instanceof DefaultSaml2AuthenticatedPrincipal principal) {
                // Read config from DB
                SsoConfiguration samlConfig = ssoConfigurationService.findByProtocolType(ProtocolType.SAML).orElse(null);
                String displayName = null;

                if (samlConfig != null && samlConfig.getSamlAttrUsername() != null && !samlConfig.getSamlAttrUsername().isBlank()) {
                    displayName = principal.getFirstAttribute(samlConfig.getSamlAttrUsername());
                }

                if (displayName == null || displayName.isBlank()) {
                    int atIndex = email.indexOf('@');
                    displayName = (atIndex > 0) ? email.substring(0, atIndex) : email;
                }
                user.setDisplayName(displayName);
            }
        } else {
            logger.debug("SAML user {} already exists in local database.", email);
            user = userOptional.get();
        }

        userRepository.save(user);
        logger.info("SAML user {} saved/updated in local database.", email);
    }
}