package com.example.demo.service;

import com.example.demo.model.ProtocolType;
import com.example.demo.model.SsoConfiguration;
import com.example.demo.repository.SsoConfigurationRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.example.demo.config.TenantContext;
import com.example.demo.model.Tenant;

import java.util.List;
import java.util.Optional;

@Service
public class SsoConfigurationService {

    private static final Logger logger = LoggerFactory.getLogger(SsoConfigurationService.class);

    @Autowired
    private SsoConfigurationRepository repository;

    @Transactional
    public Optional<SsoConfiguration> findByProtocolType(ProtocolType type) {
        // Get the tenant from the ThreadLocal
        Tenant tenant = TenantContext.getCurrentTenant();
        if (tenant == null) {
            logger.warn("No tenant in context, cannot find SSO config for type {}", type);
            return Optional.empty();
        }
        // Update repository method
        return repository.findByProtocolTypeAndTenant(type, tenant);
    }

    @Transactional
    public SsoConfiguration findByProtocolTypeOrCreate(ProtocolType type) {
        // 1. Get the current tenant
        Tenant tenant = TenantContext.getCurrentTenant();
        if (tenant == null) {
            logger.error("Cannot find or create SSO config for type {} - No tenant in context", type);
            // This should ideally not happen in a tenant-scoped request
            throw new IllegalStateException("No tenant context available.");
        }

        // 2. Use the tenant-aware repository method
        return repository.findByProtocolTypeAndTenant(type, tenant).orElseGet(() -> {
            logger.info("No configuration found for {} for tenant {}, creating default.", type, tenant.getId());
            SsoConfiguration newConfig = new SsoConfiguration();
            newConfig.setProtocolType(type);
            newConfig.setEnabled(false); // Default to disabled

            // 3. CRITICAL: Set the tenant on the new config
            newConfig.setTenant(tenant);

            return repository.save(newConfig);
        });
    }

    @Transactional
    public List<SsoConfiguration> findAllEnabled() {
        // 1. Get the current tenant
        Tenant tenant = TenantContext.getCurrentTenant();
        if (tenant == null) {
            logger.warn("Cannot find enabled SSO configs - No tenant in context");
            return List.of(); // Return an empty list
        }

        // 2. Use a new tenant-aware repository method
        return repository.findByEnabledTrueAndTenant(tenant);
    }

    @Transactional
    public SsoConfiguration save(SsoConfiguration configuration) {
        logger.info("Service received config for {}. Enabled status: {}",
                configuration.getProtocolType(), configuration.isEnabled());

        // 1. Get the current tenant and set it on the config being saved
        Tenant tenant = TenantContext.getCurrentTenant();
        if (tenant == null) {
            logger.error("Cannot save SSO config - No tenant in context");
            throw new IllegalStateException("No tenant context available.");
        }
        configuration.setTenant(tenant); // Ensure tenant is set

        // 2. Use the tenant-aware method to find the existing config
        Optional<SsoConfiguration> existingOpt = repository.findByProtocolTypeAndTenant(
                configuration.getProtocolType(),
                tenant
        );

        SsoConfiguration entityToSave;

        if (existingOpt.isPresent()) {
            entityToSave = existingOpt.get();
            logger.info("Found existing config (ID: {}). Attempting update...", entityToSave.getId());

            // --- Update ALL fields ---
            entityToSave.setEnabled(configuration.isEnabled());
            // OIDC
            entityToSave.setClientId(configuration.getClientId());
            entityToSave.setClientSecret(configuration.getClientSecret());
            entityToSave.setScope(configuration.getScope());
            entityToSave.setIssuerUri(configuration.getIssuerUri());
            entityToSave.setAuthorizationUri(configuration.getAuthorizationUri());
            entityToSave.setTokenUri(configuration.getTokenUri());
            entityToSave.setUserInfoUri(configuration.getUserInfoUri());
            entityToSave.setJwkSetUri(configuration.getJwkSetUri());
            entityToSave.setUserNameAttribute(configuration.getUserNameAttribute());
            // JWT
            entityToSave.setJwtSsoUrl(configuration.getJwtSsoUrl());
            entityToSave.setJwtRedirectUri(configuration.getJwtRedirectUri());
            entityToSave.setJwtCertificateContent(configuration.getJwtCertificateContent());

            // --- SAML FIELDS ---
            entityToSave.setIdpEntityId(configuration.getIdpEntityId());
            entityToSave.setIdpSsoUrl(configuration.getIdpSsoUrl());
            entityToSave.setIdpCertificateContent(configuration.getIdpCertificateContent());
            entityToSave.setSpEntityId(configuration.getSpEntityId());
            entityToSave.setSamlAttrEmail(configuration.getSamlAttrEmail());
            entityToSave.setSamlAttrUsername(configuration.getSamlAttrUsername());
            // --- End Field Updates ---

            // Tenant field is already set on existingOpt, no need to change
            logger.info("Updating existing entity for {}", entityToSave.getProtocolType());

        } else {
            configuration.setId(null);
            entityToSave = configuration; // This now has the tenant set from step 1
            logger.info("Saving new configuration for {}", entityToSave.getProtocolType());
        }

        try {
            SsoConfiguration savedConfig = repository.save(entityToSave);
            logger.info("Successfully saved configuration for {} with ID {}. Final enabled state: {}",
                    savedConfig.getProtocolType(), savedConfig.getId(), savedConfig.isEnabled());
            return savedConfig;
        } catch (Exception e) {
            logger.error("!!! Exception occurred during repository.save for {}: {}", entityToSave.getProtocolType(), e.getMessage(), e);
            throw new RuntimeException("Error saving configuration", e);
        }
    }
}