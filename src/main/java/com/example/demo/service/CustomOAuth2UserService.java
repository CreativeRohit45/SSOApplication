package com.example.demo.service;

import com.example.demo.model.Role;
import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.example.demo.config.TenantContext; // Import
import com.example.demo.model.Tenant; // Import

import java.util.Map;
import java.util.Optional;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private static final Logger logger = LoggerFactory.getLogger(CustomOAuth2UserService.class);

    @Autowired
    private UserRepository userRepository;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        logger.info(">>> Entering loadUser method...");

        Tenant tenant = TenantContext.getCurrentTenant();
        if (tenant == null) {
            logger.error("SSO login failed, no tenant context found.");
            throw new OAuth2AuthenticationException("Invalid tenant.");
        }

        OAuth2User oauthUser = super.loadUser(userRequest);
        Map<String, Object> attributes = oauthUser.getAttributes();
        logger.info("OAuth2 User Attributes received: {}", attributes);

        String email = (String) attributes.get("email");
        if (email == null || email.isBlank()) {
            logger.error("Email attribute is missing or empty.");
            throw new OAuth2AuthenticationException("Email not found from OAuth2 provider");
        }
        String nameAttribute = (String) attributes.get("name");

        String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails()
                .getUserInfoEndpoint().getUserNameAttributeName();
        if (userNameAttributeName == null || userNameAttributeName.isEmpty()) {
            userNameAttributeName = attributes.containsKey("sub") ? "sub" : "email";
        }
        logger.info("Using '{}' as the principal name attribute", userNameAttributeName);

        // --- SIMPLIFIED LOGIC FOR DEBUGGING ---
        logger.info(">>> Attempting DB lookup for email: {} in tenant: {}", email, tenant.getId());
        Optional<User> userOptional = userRepository.findByEmailAndTenant(email, tenant);

        User user; // Declare user variable outside the blocks

        if (userOptional.isPresent()) {
            // User exists
            user = userOptional.get();
            logger.info(">>> Found existing user: {} with role: {}", user.getEmail(), user.getRole());
            // Optionally update existing user attributes here if needed
            // Example:
            boolean updated = false;
            if (nameAttribute != null && !nameAttribute.isBlank() && !nameAttribute.equals(user.getDisplayName())) {
                user.setDisplayName(nameAttribute);
                updated = true;
                logger.info("Updating display name for user {} to '{}'", user.getEmail(), nameAttribute);
            }
            if (updated) {
                try {
                    user = userRepository.save(user); // Save updates
                    logger.info("Successfully updated existing user: {}", user.getEmail());
                } catch (Exception e) {
                    logger.error("!!! Exception occurred while updating user {}: {}", email, e.getMessage(), e);
                    // Decide how to handle update failure - maybe rethrow or just log
                }
            }

        } else {
            // User does NOT exist - Try to create
            logger.info("!!! --- User NOT found, attempting to create --- !!!");
            User newUser = new User();
            newUser.setEmail(email);

            String displayNameToSet;
            if (nameAttribute != null && !nameAttribute.isBlank()) {
                displayNameToSet = nameAttribute;
                logger.info("Using name attribute for displayName: {}", displayNameToSet);
            } else {
                int atIndex = email.indexOf('@');
                displayNameToSet = (atIndex > 0) ? email.substring(0, atIndex) : email;
                logger.info("Generating displayName from email prefix: {}", displayNameToSet);
            }
            newUser.setDisplayName(displayNameToSet);
            newUser.setRole(Role.USER);
            newUser.setPassword("SSO_USER_NO_PASSWORD_" + System.currentTimeMillis());
            newUser.setTenant(tenant);
            try {
                logger.info("Attempting to save new user...");
                user = userRepository.save(newUser); // Assign the saved user to the 'user' variable
                if (user != null && user.getId() != null) {
                    logger.info("Successfully saved new user: {} with ID: {} and role: {}", user.getEmail(), user.getId(), user.getRole());
                } else {
                    logger.error("!!! Failed to save new user, repository returned null or user without ID for email: {}", email);
                    throw new RuntimeException("Failed to save new user for email: " + email);
                }
            } catch (Exception e) {
                logger.error("!!! Exception occurred while saving new user for email {}: {}", email, e.getMessage(), e);
                // Re-throwing might be appropriate to signal failure
                throw new RuntimeException("Error saving new user: " + e.getMessage(), e);
                // Alternatively, if you want to allow login even if save fails (risky):
                // logger.warn("Proceeding without saving user due to error.");
                // user = newUser; // Use the unsaved object (will likely fail later)
            }
        }

        // --- Ensure user is not null before proceeding ---
        if (user == null) {
            logger.error("!!! User object is null after find/create logic for email: {}", email);
            throw new OAuth2AuthenticationException("Failed to load or create user");
        }

        logger.info("User object being used for principal: {} with authorities: {}", user.getEmail(), user.getAuthorities());
        logger.info("<<< Exiting loadUser method, returning DefaultOAuth2User");

        return new DefaultOAuth2User(
                user.getAuthorities(),
                attributes,
                userNameAttributeName
        );
    }
}

