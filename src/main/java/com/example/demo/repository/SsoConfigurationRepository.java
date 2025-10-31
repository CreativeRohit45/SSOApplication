package com.example.demo.repository;

import com.example.demo.model.ProtocolType;
import com.example.demo.model.SsoConfiguration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface SsoConfigurationRepository extends JpaRepository<SsoConfiguration, Long> {

    // Find a configuration by its unique protocol type
    Optional<SsoConfiguration> findByProtocolType(ProtocolType protocolType);

    // Find all enabled configurations (useful for login page)
    List<SsoConfiguration> findByEnabledTrue();
}