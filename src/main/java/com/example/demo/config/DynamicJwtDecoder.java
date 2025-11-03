package com.example.demo.config;

import com.example.demo.model.ProtocolType;
import com.example.demo.model.SsoConfiguration;
import com.example.demo.model.Tenant;
import com.example.demo.service.SsoConfigurationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
@Qualifier("jwtDecoderManual") // This is important!
public class DynamicJwtDecoder implements JwtDecoder {

    private static final Logger logger = LoggerFactory.getLogger(DynamicJwtDecoder.class);

    @Autowired
    private SsoConfigurationService ssoConfigService;

    // Cache decoders per tenant to avoid rebuilding them on every single request
    private final Map<Long, JwtDecoder> decoderCache = new ConcurrentHashMap<>();

    @Override
    public Jwt decode(String token) throws JwtException {
        Tenant tenant = TenantContext.getCurrentTenant();
        if (tenant == null) {
            throw new JwtException("No tenant context found for JWT decoding.");
        }

        SsoConfiguration jwtConfig = ssoConfigService.findByProtocolType(ProtocolType.JWT).orElse(null);

        if (jwtConfig == null || !jwtConfig.isEnabled() || jwtConfig.getJwtCertificateContent() == null || jwtConfig.getJwtCertificateContent().isBlank()) {
            logger.warn("Manual JWT flow disabled or certificate content not set for tenant {}.", tenant.getId());
            throw new JwtException("JWT Manual flow is not configured for this tenant");
        }

        // Use the cached decoder if available, otherwise build it
        JwtDecoder decoder = decoderCache.computeIfAbsent(tenant.getId(), id -> buildDecoder(jwtConfig));

        if (decoder == null) {
            // buildDecoder failed, clear cache entry to try again next time
            decoderCache.remove(tenant.getId());
            throw new JwtException("Failed to create JWT decoder for tenant " + tenant.getId());
        }

        return decoder.decode(token);
    }

    private JwtDecoder buildDecoder(SsoConfiguration jwtConfig) {
        try {
            logger.info("Building new manual JwtDecoder using certificate content from database for tenant...");
            String certificateContent = jwtConfig.getJwtCertificateContent();
            byte[] certificateBytes = certificateContent.getBytes(StandardCharsets.UTF_8);
            InputStream certInputStream = new ByteArrayInputStream(certificateBytes);

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(certInputStream);
            RSAPublicKey publicKey = (RSAPublicKey) certificate.getPublicKey();
            return NimbusJwtDecoder.withPublicKey(publicKey).build();
        } catch (Exception e) {
            logger.error("!!! Failed to create manual JwtDecoder from certificate content: {}", e.getMessage(), e);
            return null; // This will be handled by the decode method
        }
    }
}