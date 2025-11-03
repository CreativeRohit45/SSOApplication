package com.example.demo.repository;

import com.example.demo.model.ProtocolType;
import com.example.demo.model.SsoConfiguration;
import com.example.demo.model.Tenant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface SsoConfigurationRepository extends JpaRepository<SsoConfiguration, Long> {

    // Find a configuration by its unique protocol type
    Optional<SsoConfiguration> findByProtocolType(ProtocolType protocolType);

    // This is your old one, which you should replace
    List<SsoConfiguration> findByEnabledTrue();

    // --- NEW TENANT-AWARE METHODS ---

    // The new version of findByProtocolType
    Optional<SsoConfiguration> findByProtocolTypeAndTenant(ProtocolType protocolType, Tenant tenant);

    // The new version of findByEnabledTrue
    List<SsoConfiguration> findByEnabledTrueAndTenant(Tenant tenant);
}