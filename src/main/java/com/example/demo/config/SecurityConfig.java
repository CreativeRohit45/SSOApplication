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

    private final CustomOAuth2UserService customOAuth2UserService;

    @Autowired
    private UserRepository userRepository;

    // SsoConfigurationService is no longer needed here at startup
    // @Autowired
    // private SsoConfigurationService ssoConfigurationService;

    @Autowired
    public SecurityConfig(CustomOAuth2UserService customOAuth2UserService) {
        this.customOAuth2UserService = customOAuth2UserService;
        logger.info("SecurityConfig initialized with CustomOAuth2UserService: {}", customOAuth2UserService != null);
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,CustomAuthenticationSuccessHandler customHandler,
                                                   SamlAuthenticationSuccessHandler samlHandler,
                                                   // Spring will inject your @Component beans:
                                                   ClientRegistrationRepository clientRegistrationRepository,
                                                   RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) throws Exception {
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
                        // This now correctly points to the injected dynamic repository
                        .clientRegistrationRepository(clientRegistrationRepository)
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(this.customOAuth2UserService)
                                .userAuthoritiesMapper(grantedAuthoritiesMapper())
                        )
                )
                .saml2Login(saml2 -> saml2
                        .loginPage("/login")
                        .successHandler(samlHandler)
                        // This now correctly points to the injected dynamic repository
                        .relyingPartyRegistrationRepository(relyingPartyRegistrationRepository)
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

    // --- DELETED @Bean clientRegistrationRepository() ---

    // --- DELETED @Bean relyingPartyRegistrationRepository() ---

    // --- DELETED @Bean jwtDecoderManual() ---


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

                    // This service call is OK because it's at LOGIN time, not startup
                    // SsoConfiguration samlConfig = ssoConfigurationService.findByProtocolType(ProtocolType.SAML).orElse(null);
                    // We can't autowire SsoConfigurationService directly here, but we can get the user

                    // This logic is slightly risky because ssoConfigurationService is not available here
                    // It's better to handle attribute mapping inside the success handler
                    // For now, we will just use the principal name

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

            if (userEmail != null && tenant != null) {
                // --- JIT Provisioning Logic ---
                User user = userRepository.findByEmailAndTenant(userEmail, tenant).orElseGet(() -> {
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
                        // We cannot access SsoConfigurationService here, so we'll just use email
                        if (nameAttribute == null) {
                            logger.warn("Could not find name attribute, will use email prefix.");
                        }
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