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
@Order(Ordered.HIGHEST_PRECEDENCE)
public class TenantFilter extends OncePerRequestFilter {

    @Autowired
    private TenantRepository tenantRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String serverName = request.getServerName();
        String subdomain = extractSubdomain(serverName);

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
        // This is the URL from your Render dashboard screenshot
        String baseHost = "ssoapplication.onrender.com"; // <-- THIS IS THE FIX

        if (serverName != null) {
            if (serverName.equals(baseHost)) {
                // This is the super-admin login
                return null;
            }

            String productionSuffix = "." + baseHost;
            if (serverName.endsWith(productionSuffix)) {
                // This is a tenant (e.g., "rohit45.ssoapplication.onrender.com")
                return serverName.substring(0, serverName.indexOf(productionSuffix)); // "rohit45"
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
