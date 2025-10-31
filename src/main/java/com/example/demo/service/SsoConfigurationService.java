package com.example.demo.service;

import com.example.demo.model.ProtocolType;
import com.example.demo.model.SsoConfiguration;
import com.example.demo.repository.SsoConfigurationRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
public class SsoConfigurationService {

    private static final Logger logger = LoggerFactory.getLogger(SsoConfigurationService.class);

    @Autowired
    private SsoConfigurationRepository repository;

    @Transactional
    public Optional<SsoConfiguration> findByProtocolType(ProtocolType type) {
        return repository.findByProtocolType(type);
    }

    @Transactional
    public SsoConfiguration findByProtocolTypeOrCreate(ProtocolType type) {
        return repository.findByProtocolType(type).orElseGet(() -> {
            logger.info("No configuration found for {}, creating default.", type);
            SsoConfiguration newConfig = new SsoConfiguration();
            newConfig.setProtocolType(type);
            newConfig.setEnabled(false); // Default to disabled
            return repository.save(newConfig);
        });
    }

    @Transactional
    public List<SsoConfiguration> findAllEnabled() {
        return repository.findByEnabledTrue();
    }

    @Transactional
    public SsoConfiguration save(SsoConfiguration configuration) {
        logger.info("Service received config for {}. Enabled status: {}",
                configuration.getProtocolType(), configuration.isEnabled());

        Optional<SsoConfiguration> existingOpt = repository.findByProtocolType(configuration.getProtocolType());
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
            // --- UPDATE THIS LINE ---
            entityToSave.setIdpCertificateContent(configuration.getIdpCertificateContent());
            // ---
            entityToSave.setSpEntityId(configuration.getSpEntityId());
            entityToSave.setSamlAttrEmail(configuration.getSamlAttrEmail());
            entityToSave.setSamlAttrUsername(configuration.getSamlAttrUsername());
            // --- End Field Updates ---

            logger.info("Updating existing entity for {}", entityToSave.getProtocolType());

        } else {
            configuration.setId(null);
            entityToSave = configuration;
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