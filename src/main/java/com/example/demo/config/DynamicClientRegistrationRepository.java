package com.example.demo.config;

import com.example.demo.model.ProtocolType;
import com.example.demo.model.SsoConfiguration;
import com.example.demo.service.SsoConfigurationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.stereotype.Component;

@Component
public class DynamicClientRegistrationRepository implements ClientRegistrationRepository {

    private static final Logger logger = LoggerFactory.getLogger(DynamicClientRegistrationRepository.class);

    @Autowired
    private SsoConfigurationService ssoConfigService;

    @Override
    public ClientRegistration findByRegistrationId(String registrationId) {
        logger.debug("Attempting to find OIDC config for registrationId: {}", registrationId);
        // The TenantContext is automatically used by the service
        SsoConfiguration oidcConfig = ssoConfigService.findByProtocolType(ProtocolType.OIDC).orElse(null);

        if (oidcConfig == null || !oidcConfig.isEnabled()) {
            logger.warn("OIDC is not configured or disabled for current tenant. No ClientRegistration created.");
            return null;
        }

        logger.info("Dynamically building OIDC client from database for tenant...");
        ClientRegistration.Builder builder;
        if (oidcConfig.getIssuerUri() != null && !oidcConfig.getIssuerUri().isBlank()) {
            try {
                builder = ClientRegistrations.fromIssuerLocation(oidcConfig.getIssuerUri());
            } catch (Exception e) {
                logger.error("!!! Failed to configure OIDC from Issuer-URI: {}. Error: {}", oidcConfig.getIssuerUri(), e.getMessage());
                return null; // Return null on discovery failure
            }
        } else {
            logger.info("Using manual OIDC endpoints for tenant.");
            builder = ClientRegistration.withRegistrationId(registrationId)
                    .authorizationUri(oidcConfig.getAuthorizationUri())
                    .tokenUri(oidcConfig.getTokenUri())
                    .userInfoUri(oidcConfig.getUserInfoUri())
                    .jwkSetUri(oidcConfig.getJwkSetUri())
                    .userNameAttributeName(oidcConfig.getUserNameAttribute());
        }

        String[] scopes = new String[]{"openid", "email", "profile"};
        if (oidcConfig.getScope() != null && !oidcConfig.getScope().isBlank()) {
            scopes = oidcConfig.getScope().trim().split("\\s*,\\s*");
        }

        return builder
                .registrationId(registrationId) // Use the ID from the request
                .clientId(oidcConfig.getClientId())
                .clientSecret(oidcConfig.getClientSecret())
                .scope(scopes)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientName("MiniOrange OIDC")
                .build();
    }
}