package com.example.demo.model;

import jakarta.persistence.*;

@Entity
@Table(name = "sso_configuration", uniqueConstraints = {
        @UniqueConstraint(columnNames = {"protocol_type", "tenant_id"}) // Ensure only one config per type
})
public class SsoConfiguration {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(name = "protocol_type", nullable = false, unique = true)
    private ProtocolType protocolType;

    @Column(nullable = false)
    private boolean enabled = false; // Default to disabled

    // Common fields
    @Column(length = 500)
    private String clientId;
    @Column(length = 500)
    private String clientSecret; // Consider encryption

    // OIDC specific (can be null for others)
    @Column(length = 1000)
    private String scope;
    @Column(length = 1000)
    private String issuerUri;
    @Column(length = 1000)
    private String authorizationUri;
    @Column(length = 1000)
    private String tokenUri;
    @Column(length = 1000)
    private String userInfoUri;
    @Column(length = 1000)
    private String jwkSetUri;
    private String userNameAttribute;

    // Manual JWT specific (can be null for others)
    @Column(length = 1000)
    private String jwtSsoUrl;
    @Column(length = 1000)
    private String jwtRedirectUri;
    @Column(columnDefinition = "TEXT") // Use TEXT for cert content
    private String jwtCertificateContent;

    // --- SAML FIELDS (Uncommented) ---
    @Column(length = 1000)
    private String idpEntityId;
    @Column(length = 1000)
    private String idpSsoUrl;
    @Column(columnDefinition = "TEXT") // Store certificate content
    private String idpCertificateContent;
    @Column(length = 1000)
    private String spEntityId;
    private String samlAttrEmail;
    private String samlAttrUsername;
    // --- END SAML FIELDS ---

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    // --- Getters and Setters ---
    // (OIDC and JWT Getters/Setters)
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public ProtocolType getProtocolType() { return protocolType; }
    public void setProtocolType(ProtocolType protocolType) { this.protocolType = protocolType; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }
    public String getClientSecret() { return clientSecret; }
    public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }
    public String getScope() { return scope; }
    public void setScope(String scope) { this.scope = scope; }
    public String getIssuerUri() { return issuerUri; }
    public void setIssuerUri(String issuerUri) { this.issuerUri = issuerUri; }
    public String getAuthorizationUri() { return authorizationUri; }
    public void setAuthorizationUri(String authorizationUri) { this.authorizationUri = authorizationUri; }
    public String getTokenUri() { return tokenUri; }
    public void setTokenUri(String tokenUri) { this.tokenUri = tokenUri; }
    public String getUserInfoUri() { return userInfoUri; }
    public void setUserInfoUri(String userInfoUri) { this.userInfoUri = userInfoUri; }
    public String getJwkSetUri() { return jwkSetUri; }
    public void setJwkSetUri(String jwkSetUri) { this.jwkSetUri = jwkSetUri; }
    public String getUserNameAttribute() { return userNameAttribute; }
    public void setUserNameAttribute(String userNameAttribute) { this.userNameAttribute = userNameAttribute; }
    public String getJwtSsoUrl() { return jwtSsoUrl; }
    public void setJwtSsoUrl(String jwtSsoUrl) { this.jwtSsoUrl = jwtSsoUrl; }
    public String getJwtRedirectUri() { return jwtRedirectUri; }
    public void setJwtRedirectUri(String jwtRedirectUri) { this.jwtRedirectUri = jwtRedirectUri; }
    public String getJwtCertificateContent() { return jwtCertificateContent; }
    public void setJwtCertificateContent(String jwtCertificateContent) { this.jwtCertificateContent = jwtCertificateContent; }

    // --- SAML GETTERS/SETTERS (Uncommented) ---
    public String getIdpEntityId() { return idpEntityId; }
    public void setIdpEntityId(String idpEntityId) { this.idpEntityId = idpEntityId; }
    public String getIdpSsoUrl() { return idpSsoUrl; }
    public void setIdpSsoUrl(String idpSsoUrl) { this.idpSsoUrl = idpSsoUrl; }
    public String getIdpCertificateContent() { return idpCertificateContent; }
    public void setIdpCertificateContent(String idpCertificateContent) { this.idpCertificateContent = idpCertificateContent; }
    public String getSpEntityId() { return spEntityId; }
    public void setSpEntityId(String spEntityId) { this.spEntityId = spEntityId; }
    public String getSamlAttrEmail() { return samlAttrEmail; }
    public void setSamlAttrEmail(String samlAttrEmail) { this.samlAttrEmail = samlAttrEmail; }
    public String getSamlAttrUsername() { return samlAttrUsername; }
    public void setSamlAttrUsername(String samlAttrUsername) { this.samlAttrUsername = samlAttrUsername; }

    public Tenant getTenant() { return tenant; }
    public void setTenant(Tenant tenant) { this.tenant = tenant; }
}