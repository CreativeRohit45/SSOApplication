package com.example.demo.config;

import java.io.IOException;
import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors; // Import Collectors

import org.slf4j.Logger; // Import Logger
import org.slf4j.LoggerFactory; // Import LoggerFactory
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    // --- Add Logger ---
    private static final Logger logger = LoggerFactory.getLogger(CustomAuthenticationSuccessHandler.class);

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException, ServletException {

        Object testFlag = request.getSession().getAttribute("OIDC_TEST_IN_PROGRESS");
        if (testFlag != null && testFlag.equals(true) && authentication instanceof OAuth2AuthenticationToken) {

            // 1. Clear the flag
            request.getSession().removeAttribute("OIDC_TEST_IN_PROGRESS");

            // 2. Get the user and their attributes
            OAuth2User principal = ((OAuth2AuthenticationToken) authentication).getPrincipal();
            Map<String, Object> attributes = principal.getAttributes();

            // 3. Put data on the request for the results page
            request.setAttribute("test_status", "SUCCESS");
            request.setAttribute("test_attributes", attributes);

            // 4. Forward to the results page (don't redirect)
            logger.info("OIDC test successful. Forwarding to results page.");
            request.getRequestDispatcher("/oauth-test-results").forward(request, response);
            return; // IMPORTANT: Stop execution here
        }

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

        // --- Log the authorities ---
        String roles = authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(", "));
        logger.info("User '{}' authenticated successfully with authorities: {}", authentication.getName(), roles);


        // Redirect based on role
        boolean isAdmin = authorities.stream()
                .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("ROLE_ADMIN"));

        if (isAdmin) {
            logger.info("Redirecting user to /admin");
            response.sendRedirect("/admin");
        } else {
            logger.info("Redirecting user to /home");
            response.sendRedirect("/home");
        }
    }
}
