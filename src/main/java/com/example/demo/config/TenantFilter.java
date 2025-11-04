package com.example.demo.config;

import com.example.demo.model.Tenant;
import com.example.demo.repository.TenantRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered; // <-- IMPORT THIS
import org.springframework.core.annotation.Order; // <-- IMPORT THIS
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE) // <-- THIS IS THE FIX (changed from @Order(1))
public class TenantFilter extends OncePerRequestFilter {

    @Autowired
    private TenantRepository tenantRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String serverName = request.getServerName(); // "rohit45.localhost"
        String subdomain = extractSubdomain(serverName); // "rohit45"

        if (subdomain != null) {
            // Find the tenant by its subdomain
            Tenant tenant = tenantRepository.findBySubdomain(subdomain).orElse(null);
            TenantContext.setCurrentTenant(tenant);
        }

        try {
            filterChain.doFilter(request, response);
        } finally {
            // CRITICAL: Always clear the context after the request is done
            TenantContext.clear();
        }
    }

    private String extractSubdomain(String serverName) {

        // --- 1. PRODUCTION DOMAIN ---
        // Replace this with your app's base URL from Render
        String baseHost = "my-sso-app.onrender.com"; // <-- IMPORTANT: UPDATE THIS

        if (serverName != null) {
            if (serverName.equals(baseHost)) {
                // This is the super-admin login (e.g., my-sso-app.onrender.com)
                return null;
            }

            String productionSuffix = "." + baseHost;
            if (serverName.endsWith(productionSuffix)) {
                // This is a tenant (e.g., "pratik.my-sso-app.onrender.com")
                return serverName.substring(0, serverName.indexOf(productionSuffix)); // "pratik"
            }

            // --- 2. LOCALHOST (for testing) ---
            String localSuffix = ".localhost";
            if (serverName.endsWith(localSuffix)) {
                return serverName.substring(0, serverName.indexOf(localSuffix)); // "rohit45"
            }
        }

        // No subdomain (e.g., "localhost" or base render URL)
        return null;
    }
}