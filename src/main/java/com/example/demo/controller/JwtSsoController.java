package com.example.demo.controller;

import com.example.demo.config.TenantContext;
import com.example.demo.model.*;
import com.example.demo.repository.UserRepository;
import com.example.demo.service.SsoConfigurationService;
import jakarta.servlet.http.HttpServletRequest; // <-- THIS IMPORT IS ALREADY HERE, BUT IT'S NOW USED IN A NEW PLACE
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder; // <-- 1. ADD THIS NEW IMPORT

import java.io.IOException;

@Controller
public class JwtSsoController {

    private static final Logger logger = LoggerFactory.getLogger(JwtSsoController.class);

    // --- REMOVED @Value annotations ---

    @Autowired
    @Qualifier("jwtDecoderManual")
    private JwtDecoder jwtDecoderManual;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    @Qualifier("customAuthenticationSuccessHandler")
    private AuthenticationSuccessHandler authenticationSuccessHandler;

    // --- INJECT SsoConfigurationService ---
    @Autowired
    private SsoConfigurationService ssoConfigurationService;

    private SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

    /**
     * Redirects the user to the miniOrange manual JWT SSO login page.
     */
    @GetMapping("/sso/jwt/login")
    public String redirectToMiniOrangeJwtSso(RedirectAttributes redirectAttributes,
                                             HttpServletRequest request) { // <-- 2. ADD HttpServletRequest request HERE

        // --- Fetch JWT config from DB ---
        SsoConfiguration jwtConfig = ssoConfigurationService.findByProtocolType(ProtocolType.JWT).orElse(null);

        if (jwtConfig == null || !jwtConfig.isEnabled()) {
            logger.warn("Attempted to start manual JWT flow, but it is disabled or not configured.");
            redirectAttributes.addFlashAttribute("errorMessage", "JWT SSO is not configured or disabled.");
            return "redirect:/login";
        }

        // --- 3. REPLACE THE OLD URL-BUILDING LOGIC WITH THIS ---
        // Build the dynamic redirect_uri from the current request
        // e.g., "https://pratik.my-sso-app.onrender.com/login/jwt/callback"
        String dynamicRedirectUri = ServletUriComponentsBuilder.fromRequest(request)
                .replacePath("/login/jwt/callback") // Change the path
                .replaceQuery(null) // Remove any query params
                .build()
                .toUriString(); // This will correctly use "https:"

        logger.info("Dynamic JWT Redirect URI built: {}", dynamicRedirectUri);

        // Build the URL with client_id from DB and DYNAMIC redirect_uri
        String url = UriComponentsBuilder.fromHttpUrl(jwtConfig.getJwtSsoUrl())
                .queryParam("client_id", jwtConfig.getClientId())
                .queryParam("redirect_uri", dynamicRedirectUri) // <-- Use the new dynamic URL
                .toUriString();
        // --- END OF CHANGES ---

        logger.info("Redirecting to miniOrange JWT SSO: {}", url);
        return "redirect:" + url;
    }

    /**
     * Handles the callback from miniOrange with the JWT.
     */
    @GetMapping("/login/jwt/callback")
    @Transactional
    public void handleJwtCallback(@RequestParam("id_token") String token, // Or "token"? Verify!
                                  HttpServletRequest request,
                                  HttpServletResponse response) throws IOException {

        logger.info("Received JWT callback token for manual flow.");

        Tenant tenant = TenantContext.getCurrentTenant();
        if (tenant == null) {
            logger.error("JWT login failed, no tenant context found.");
            response.sendRedirect("/login?error=sso_unexpected_error");
            return;
        }

        SsoConfiguration jwtConfig = ssoConfigurationService.findByProtocolType(ProtocolType.JWT).orElse(null);

        try {
            // 1. Validate the JWT using the CERTIFICATE-based decoder
            Jwt jwt = jwtDecoderManual.decode(token);
            logger.info("Manual JWT decoded successfully. Claims: {}", jwt.getClaims());

            // --- Optional: Manual Issuer validation ---
            if (jwtConfig != null && jwtConfig.getIssuerUri() != null && !jwtConfig.getIssuerUri().isBlank()) {
                String expectedIssuer = jwtConfig.getIssuerUri();
                String actualIssuer = jwt.getIssuer().toString();
                if (!expectedIssuer.equals(actualIssuer)) {
                    logger.error("JWT Issuer validation failed. Expected '{}', but was '{}'", expectedIssuer, actualIssuer);
                    throw new JwtException("Invalid JWT Issuer");
                }
                logger.info("JWT Issuer validated successfully.");
            }
            // --- End Optional Validation ---

            // 2. Extract Claims
            String email = jwt.getClaimAsString("email");
            String name = jwt.getClaimAsString("name");

            if (email == null || email.isBlank()) {
                logger.error("Email claim missing in JWT for manual flow.");
                throw new JwtException("Email claim missing in JWT");
            }

            // 3. Find or Create User (JIT Provisioning)
            User user = userRepository.findByEmailAndTenant(email, tenant)
                    .orElseGet(() -> {
                        logger.warn("Manual JWT Flow - User not found in DB for email: {}. Creating.", email);
                        User newUser = new User();
                        newUser.setEmail(email);
                        String displayNameToSet;
                        if (name != null && !name.isBlank()) {
                            displayNameToSet = name;
                        } else {
                            int atIndex = email.indexOf('@');
                            displayNameToSet = (atIndex > 0) ? email.substring(0, atIndex) : email;
                        }
                        newUser.setDisplayName(displayNameToSet);
                        newUser.setRole(Role.END_USER);
                        newUser.setTenant(tenant);
                        newUser.setPassword("JWT_USER_NO_PASSWORD_" + System.currentTimeMillis());
                        try {
                            User savedUser = userRepository.save(newUser);
                            logger.info("Manual JWT Flow - Saved new user: {}", savedUser.getEmail());
                            return savedUser;
                        } catch (Exception e) {
                            logger.error("!!! Manual JWT Flow - Error saving new user {}: {}", email, e.getMessage(), e);
                            throw new RuntimeException("Error saving JWT user", e);
                        }
                    });

            // 4. Create Authentication object
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    user, null, user.getAuthorities()
            );

            // 5. Manually set the Authentication in the SecurityContext
            var context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);

            // 6. Save the context to the HTTP session
            securityContextRepository.saveContext(context, request, response);
            logger.info("Manual JWT Flow - Authentication set in SecurityContext and saved to session for user: {}", authentication.getName());

            // 7. Use the shared success handler to redirect based on role
            authenticationSuccessHandler.onAuthenticationSuccess(request, response, authentication);

        } catch (JwtException e) {
            logger.error("Manual JWT Flow - Error validating JWT token: {}", e.getMessage());
            response.sendRedirect("/login?error=jwt_invalid");
        } catch (Exception e) {
            logger.error("Manual JWT Flow - Error during callback processing: {}", e.getMessage(), e);
            response.sendRedirect("/login?error=jwt_processing_failed");
        }
    }
}