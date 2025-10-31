package com.example.demo.config;

import com.example.demo.model.ProtocolType;
import com.example.demo.model.SsoConfiguration;
import com.example.demo.service.SsoConfigurationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Iterator;

/**
 * Dynamically loads SAML 2.0 Relying Party configurations from the database.
 * This bean is automatically picked up by Spring Security's SAML infrastructure.
 */
@Component
public class DynamicRelyingPartyRegistrationRepository implements RelyingPartyRegistrationRepository, Iterable<RelyingPartyRegistration> {

    private static final Logger logger = LoggerFactory.getLogger(DynamicRelyingPartyRegistrationRepository.class);

    @Autowired
    private SsoConfigurationService ssoConfigService;

    // The registrationId we use in our app (from login.html and config-saml.html)
    // This must match what's in your SsoConfiguration table for spEntityId
    // Let's assume you use "miniorange-saml" as the default
    private static final String DEFAULT_REGISTRATION_ID = "miniorange-saml";

    /**
     * Finds a SAML configuration by its registrationId.
     */
    @Override
    public RelyingPartyRegistration findByRegistrationId(String registrationId) {
        logger.debug("Attempting to find SAML config for registrationId: {}", registrationId);

        // Fetch the one SAML config from the DB
        return ssoConfigService.findByProtocolType(ProtocolType.SAML)
                .filter(SsoConfiguration::isEnabled) // Check if it's enabled
                // Ensure the requested ID matches what we expect
                .filter(config -> registrationId.equals(this.getRegistrationId(config)))
                .map(this::convertConfigToRegistration)
                .orElse(null); // Return null if not found, disabled, or ID doesn't match
    }

    /**
     * Provides an iterator over all enabled SAML configurations.
     */
    @Override
    public Iterator<RelyingPartyRegistration> iterator() {
        return ssoConfigService.findByProtocolType(ProtocolType.SAML).stream()
                .filter(SsoConfiguration::isEnabled)
                .map(this::convertConfigToRegistration)
                .iterator();
    }

    /**
     * Helper method to convert our SsoConfiguration entity into a Spring Security
     * RelyingPartyRegistration object.
     */
    private RelyingPartyRegistration convertConfigToRegistration(SsoConfiguration config) {
        String registrationId = getRegistrationId(config);
        logger.info("Building SAML RelyingPartyRegistration for: {}", registrationId);

        try {
            // 1. Load the SAML signing certificate from the config text
            X509Certificate idpCertificate = parseCertificate(config.getIdpCertificateContent());

            // 2. Create the SAML credential
            Saml2X509Credential credential = Saml2X509Credential.verification(idpCertificate);

            // 3. Build the RelyingPartyRegistration
            return RelyingPartyRegistration.withRegistrationId(registrationId)
                    // Our (Service Provider) details
                    .entityId(config.getSpEntityId()) // Use SP Entity ID from DB
                    .assertionConsumerServiceLocation("{baseUrl}/login/saml2/sso/{registrationId}")

                    // Their (Identity Provider) details
                    .assertingPartyDetails(party -> party
                            .entityId(config.getIdpEntityId())
                            .singleSignOnServiceLocation(config.getIdpSsoUrl())
                            .verificationX509Credentials(c -> c.add(credential))
                            .wantAuthnRequestsSigned(false) // Common setting, makes setup simpler
                    )
                    .build();

        } catch (Exception e) {
            logger.error("Failed to configure SAML provider '{}': {}", registrationId, e.getMessage(), e);
            return null; // This provider will be disabled
        }
    }

    /**
     * Converts a PEM certificate string (from DB) into an X509Certificate object.
     */
    private X509Certificate parseCertificate(String pemCertificate) throws Exception {
        if (pemCertificate == null || pemCertificate.isBlank()) {
            throw new IllegalArgumentException("SAML certificate content is null or empty.");
        }
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        // Remove potential extra whitespace/newlines
        String cleanPem = pemCertificate.trim();
        byte[] certificateBytes = cleanPem.getBytes(StandardCharsets.UTF_8);
        try (InputStream certStream = new ByteArrayInputStream(certificateBytes)) {
            return (X509Certificate) factory.generateCertificate(certStream);
        }
    }

    /**
     * Helper to determine the registrationId to use.
     * Extracts it from the end of the SP Entity ID or defaults.
     */
    private String getRegistrationId(SsoConfiguration config) {
        if (config.getSpEntityId() != null && config.getSpEntityId().contains("/")) {
            String[] parts = config.getSpEntityId().split("/");
            if (parts.length > 0) {
                return parts[parts.length - 1]; // Use last part of SP Entity ID
            }
        }
        return DEFAULT_REGISTRATION_ID; // Fallback
    }
}