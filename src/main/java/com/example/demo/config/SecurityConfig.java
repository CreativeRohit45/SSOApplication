package com.example.demo.config;

import com.example.demo.model.*;
import com.example.demo.repository.UserRepository;
import com.example.demo.service.CustomOAuth2UserService;
import com.example.demo.service.SsoConfigurationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
// OIDC Imports
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
// JWT Imports
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
// SAML Imports
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.core.Saml2X509Credential;
// Other imports
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;


@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    // --- REMOVED @Value Injections for JWT ---

    private final CustomOAuth2UserService customOAuth2UserService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private SsoConfigurationService ssoConfigurationService;

    // --- REMOVED Injections for ClientRegistrationRepository and RelyingPartyRegistrationRepository ---

    @Autowired
    public SecurityConfig(CustomOAuth2UserService customOAuth2UserService) {
        this.customOAuth2UserService = customOAuth2UserService;
        logger.info("SecurityConfig initialized with CustomOAuth2UserService: {}", customOAuth2UserService != null);
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,CustomAuthenticationSuccessHandler customHandler,
                                                   SamlAuthenticationSuccessHandler samlHandler) throws Exception {
        logger.info(">>> Configuring SecurityFilterChain...");
        http
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers(
                                "/register", "/login",
                                "/sso/jwt/login", "/login/jwt/callback",
                                "/css/**", "/js/**").permitAll()

                        // --- UPDATED ROLES ---
                        .requestMatchers("/super-admin/**").hasRole("SUPER_ADMIN")
                        .requestMatchers("/admin/**").hasRole("CUSTOMER_ADMIN")
                        .requestMatchers("/home", "/oauth-test-results").hasAnyRole("CUSTOMER_ADMIN", "END_USER")

                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .successHandler(customHandler)
                        .permitAll()
                )

                // --- THIS IS THE NEW DYNAMIC CONFIGURATION ---

                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login")
                        .successHandler(customHandler)
                        // This dynamically provides the OIDC configuration
                        .clientRegistrationRepository(clientRegistrationRepository())
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(this.customOAuth2UserService)
                                .userAuthoritiesMapper(grantedAuthoritiesMapper())
                        )
                )
                .saml2Login(saml2 -> saml2
                        .loginPage("/login")
                        .successHandler(samlHandler)
                        // This dynamically provides the SAML configuration
                        .relyingPartyRegistrationRepository(relyingPartyRegistrationRepository())
                )

                // --- END DYNAMIC CONFIGURATION ---

                .logout(logout -> logout
                        .logoutSuccessUrl("/login?logout")
                        .permitAll()
                )
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers(
                                "/login/oauth2/code/**",
                                "/login/jwt/callback/**",
                                "/login/saml2/sso/**"
                        )
                );

        logger.info("<<< SecurityFilterChain configuration complete.");
        return http.build();
    }

    // --- Dynamic OIDC Configuration Bean ---
    // This bean is now called *by* the securityFilterChain, not at startup
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        SsoConfiguration oidcConfig = ssoConfigurationService.findByProtocolType(ProtocolType.OIDC).orElse(null);

        // If OIDC is disabled or not found, return an EMPTY repository.
        if (oidcConfig == null || !oidcConfig.isEnabled()) {
            logger.warn("OIDC is not configured or disabled. No ClientRegistration created.");
            return new InMemoryClientRegistrationRepository();
        }

        logger.info("Dynamically configuring OIDC client from database...");
        ClientRegistration.Builder builder;
        if (oidcConfig.getIssuerUri() != null && !oidcConfig.getIssuerUri().isBlank()) {
            try {
                builder = ClientRegistrations.fromIssuerLocation(oidcConfig.getIssuerUri());
            } catch (Exception e) {
                logger.error("!!! Failed to configure OIDC from Issuer-URI: {}. Error: {}", oidcConfig.getIssuerUri(), e.getMessage());
                return new InMemoryClientRegistrationRepository(); // Return empty on discovery failure
            }
        } else {
            logger.info("Using manual OIDC endpoints.");
            builder = ClientRegistration.withRegistrationId("miniorange")
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
        ClientRegistration registration = builder
                .registrationId("miniorange") // This must match the login button link
                .clientId(oidcConfig.getClientId())
                .clientSecret(oidcConfig.getClientSecret())
                .scope(scopes)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientName("MiniOrange OIDC")
                .build();

        return new InMemoryClientRegistrationRepository(registration);
    }

    // --- Dynamic SAML Configuration Bean ---
    // This bean is now called *by* the securityFilterChain
    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
        SsoConfiguration samlConfig = ssoConfigurationService.findByProtocolType(ProtocolType.SAML).orElse(null);

        if (samlConfig == null || !samlConfig.isEnabled()) {
            logger.warn("SAML is not configured or disabled. No RelyingPartyRegistration created.");
            return new InMemoryRelyingPartyRegistrationRepository();
        }

        logger.info("Dynamically configuring SAML relying party from database...");

        Saml2X509Credential verificationCredential;
        try {
            // This logic assumes you store the *full certificate content* in the DB
            String certContent = samlConfig.getIdpCertificateContent();
            if (certContent == null || certContent.isBlank()) {
                throw new IOException("SAML certificate content is empty in database.");
            }
            byte[] certificateBytes = certContent.getBytes(StandardCharsets.UTF_8);
            InputStream certInputStream = new ByteArrayInputStream(certificateBytes);

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(certInputStream);
            verificationCredential = Saml2X509Credential.verification(certificate);

        } catch (Exception e) {
            logger.error("!!! FAILED to load SAML IdP certificate from database content: {}", e.getMessage(), e);
            return new InMemoryRelyingPartyRegistrationRepository();
        }

        // Determine the registrationId from the SP entity ID
        String registrationId = "miniorange-saml"; // Default
        if (samlConfig.getSpEntityId() != null && samlConfig.getSpEntityId().contains("/")) {
            String[] parts = samlConfig.getSpEntityId().split("/");
            if (parts.length > 0) {
                registrationId = parts[parts.length - 1];
            }
        }
        logger.info("Using SAML registrationId: {}", registrationId);

        RelyingPartyRegistration registration = RelyingPartyRegistration
                .withRegistrationId(registrationId) // Must match login.html link
                .assertingPartyDetails(party -> party
                        .entityId(samlConfig.getIdpEntityId())
                        .singleSignOnServiceLocation(samlConfig.getIdpSsoUrl())
                        .verificationX509Credentials(c -> c.add(verificationCredential))
                        .wantAuthnRequestsSigned(false)
                )
                .entityId(samlConfig.getSpEntityId()) // Your SP Entity ID
                .assertionConsumerServiceLocation("{baseUrl}/login/saml2/sso/{registrationId}")
                .build();

        return new InMemoryRelyingPartyRegistrationRepository(registration);
    }
    // --- END SAML Bean ---


    // --- Dynamic JWT Decoder Bean (Using Content) ---
    @Bean
    @Qualifier("jwtDecoderManual")
    public JwtDecoder jwtDecoderManual() {
        SsoConfiguration jwtConfig = ssoConfigurationService.findByProtocolType(ProtocolType.JWT).orElse(null);

        if (jwtConfig == null || !jwtConfig.isEnabled() || jwtConfig.getJwtCertificateContent() == null || jwtConfig.getJwtCertificateContent().isBlank()) {
            logger.warn("Manual JWT flow disabled or certificate content not set. Creating a NO-OP decoder.");
            return (token) -> { throw new JwtException("JWT Manual flow is not configured"); };
        }

        try {
            logger.info("Creating manual JwtDecoder using certificate content from database...");
            String certificateContent = jwtConfig.getJwtCertificateContent();
            byte[] certificateBytes = certificateContent.getBytes(StandardCharsets.UTF_8);
            InputStream certInputStream = new ByteArrayInputStream(certificateBytes);

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(certInputStream);
            RSAPublicKey publicKey = (RSAPublicKey) certificate.getPublicKey();
            NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(publicKey).build();
            logger.info("Manual JwtDecoder created successfully from database content.");
            return jwtDecoder;

        } catch (Exception e) {
            logger.error("!!! Failed to create manual JwtDecoder from certificate content: {}", e.getMessage(), e);
            return (token) -> { throw new JwtException("Failed to load JWT validation key from DB: " + e.getMessage()); };
        }
    }

    // --- GrantedAuthoritiesMapper (SAML logic included) ---
    @Bean
    @Transactional
    public GrantedAuthoritiesMapper grantedAuthoritiesMapper() {
        return (authorities) -> {
            logger.info(">>> GrantedAuthoritiesMapper - Incoming authorities: {}", authorities);
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>(authorities);
            final AtomicReference<String> userEmailRef = new AtomicReference<>();
            final AtomicReference<Map<String, ?>> userAttributesRef = new AtomicReference<>();


            authorities.forEach(authority -> {
                String email = null;
                Map<String, ?> attributes = null;

                if (authority instanceof OidcUserAuthority oidcUserAuthority) {
                    attributes = oidcUserAuthority.getAttributes();
                    email = oidcUserAuthority.getIdToken().getEmail();
                    if (email == null) {
                        email = oidcUserAuthority.getUserInfo().getEmail();
                    }
                    logger.info("GrantedAuthoritiesMapper - Extracted email from OidcUserAuthority: {}", email);
                } else if (authority instanceof OAuth2UserAuthority oauth2UserAuthority) {
                    attributes = oauth2UserAuthority.getAttributes();
                    email = (String) attributes.get("email");
                    logger.info("GrantedAuthoritiesMapper - Extracted email from OAuth2UserAuthority attributes: {}", email);
                }
                else if (authority instanceof Saml2AuthenticatedPrincipal) {
                    Saml2AuthenticatedPrincipal samlPrincipal = (Saml2AuthenticatedPrincipal) authority;
                    attributes = samlPrincipal.getAttributes(); // This is Map<String, List<Object>>

                    SsoConfiguration samlConfig = ssoConfigurationService.findByProtocolType(ProtocolType.SAML).orElse(null);
                    if (samlConfig != null && samlConfig.getSamlAttrEmail() != null && !samlConfig.getSamlAttrEmail().isBlank()) {
                        String emailAttrName = samlConfig.getSamlAttrEmail();
                        if (attributes.containsKey(emailAttrName)) {
                            Object emailAttr = attributes.get(emailAttrName);
                            if (emailAttr instanceof List && !((List<?>) emailAttr).isEmpty()) {
                                email = ((List<?>) emailAttr).get(0).toString();
                            } else if (emailAttr != null) {
                                email = emailAttr.toString();
                            }
                            logger.info("GrantedAuthoritiesMapper - Extracted email from SAML attribute '{}': {}", emailAttrName, email);
                        }
                    }

                    if (email == null) {
                        email = samlPrincipal.getName();
                        logger.info("GrantedAuthoritiesMapper - Extracted email from SAML Principal NameID: {}", email);
                    }
                }

                if (email != null) {
                    userEmailRef.set(email);
                    if (attributes != null) userAttributesRef.set(attributes);
                }
            });

            String userEmail = userEmailRef.get();
            Map<String, ?> userAttributes = userAttributesRef.get();

            Tenant tenant = TenantContext.getCurrentTenant(); // <-- ADD THIS
            if (tenant == null && userEmail != null) {
                // This might be a SUPER_ADMIN login, check for null tenant
                User superAdmin = userRepository.findByEmailAndTenantIsNull(userEmail).orElse(null);
                if (superAdmin != null) {
                    mappedAuthorities.addAll(superAdmin.getAuthorities());
                    return mappedAuthorities;
                }
                // If not a super admin, and no tenant, it's an error
                logger.warn("No tenant in context for SSO user {}", userEmail);
                return mappedAuthorities;
            }

            if (userEmail != null) {
                // --- JIT Provisioning Logic ---
                User user = userRepository.findByEmail(userEmail).orElseGet(() -> {
                    logger.warn("GrantedAuthoritiesMapper - User not found in DB for email: {}. Creating new user.", userEmail);
                    User newUser = new User();
                    newUser.setEmail(userEmail);

                    String nameAttribute = null;
                    if (userAttributes != null) {
                        // OIDC/JWT Check
                        Object nameObj = userAttributes.get("name");
                        if (nameObj != null) nameAttribute = nameObj.toString();

                        if (nameAttribute == null) {
                            nameObj = userAttributes.get("username"); // JWT
                            if (nameObj != null) nameAttribute = nameObj.toString();
                        }

                        // --- SAML Fallback ---
                        if (nameAttribute == null) {
                            SsoConfiguration samlConfig = ssoConfigurationService.findByProtocolType(ProtocolType.SAML).orElse(null);
                            if(samlConfig != null && samlConfig.getSamlAttrUsername() != null && !samlConfig.getSamlAttrUsername().isBlank()) {
                                String usernameAttrName = samlConfig.getSamlAttrUsername();
                                if (userAttributes.containsKey(usernameAttrName)) {
                                    Object attr = userAttributes.get(usernameAttrName);
                                    if (attr instanceof List && !((List<?>) attr).isEmpty()) {
                                        nameAttribute = ((List<?>)attr).get(0).toString();
                                    } else if (attr != null) {
                                        nameAttribute = attr.toString();
                                    }
                                    logger.info("GrantedAuthoritiesMapper - Extracted name from SAML attribute '{}': {}", usernameAttrName, nameAttribute);
                                }
                            }
                        }
                        // --- END SAML FALLBACK ---
                    }

                    String displayNameToSet;
                    if (nameAttribute != null && !nameAttribute.isBlank()) {
                        displayNameToSet = nameAttribute;
                        logger.info("GrantedAuthoritiesMapper - Using name attribute for displayName: {}", displayNameToSet);
                    } else {
                        int atIndex = userEmail.indexOf('@');
                        displayNameToSet = (atIndex > 0) ? userEmail.substring(0, atIndex) : userEmail;
                        logger.info("GrantedAuthoritiesMapper - Generating displayName from email prefix: {}", displayNameToSet);
                    }
                    newUser.setDisplayName(displayNameToSet);
                    newUser.setRole(Role.END_USER);
                    newUser.setPassword("SSO_USER_NO_PASSWORD_" + System.currentTimeMillis());
                    newUser.setTenant(tenant);

                    try {
                        logger.info("GrantedAuthoritiesMapper - Attempting to save new user...");
                        User savedUser = userRepository.save(newUser);
                        if (savedUser != null && savedUser.getId() != null) {
                            logger.info("GrantedAuthoritiesMapper - Successfully saved new user: {} with ID: {} and role: {}", savedUser.getEmail(), savedUser.getId(), savedUser.getRole());
                            return savedUser;
                        } else {
                            logger.error("!!! GrantedAuthoritiesMapper - Failed to save new user...");
                            return newUser;
                        }
                    } catch (Exception e) {
                        logger.error("!!! GrantedAuthoritiesMapper - Exception occurred while saving new user {}: {}", userEmail, e.getMessage(), e);
                        return newUser;
                    }
                });

                // Add authorities from the found or newly created user
                if (user != null && user.getAuthorities() != null) {
                    logger.info("GrantedAuthoritiesMapper - User object fetched/created. Role from DB/Object: {}", user.getRole());
                    logger.info("GrantedAuthoritiesMapper - Adding authorities from DB/new user {}: {}", user.getEmail(), user.getAuthorities());
                    mappedAuthorities.addAll(user.getAuthorities());
                } else {
                    logger.error("GrantedAuthoritiesMapper - User object was null or had no authorities after find/create for email: {}", userEmail);
                }

            } else {
                logger.warn("GrantedAuthoritiesMapper - Could not extract email from authorities: {}", authorities);
            }

            logger.info("<<< GrantedAuthoritiesMapper - Returning mapped authorities: {}", mappedAuthorities);
            return mappedAuthorities;
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}