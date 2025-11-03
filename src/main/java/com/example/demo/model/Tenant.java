package com.example.demo.model;

import jakarta.persistence.*;
import java.util.Set;

@Entity
@Table(name = "tenants")
public class Tenant {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false, length = 100)
    private String subdomain; // "rohit45", "prajwal"

    // --- Relationships ---

    // A tenant has many users
    @OneToMany(mappedBy = "tenant", cascade = CascadeType.ALL, orphanRemoval = true)
    private Set<User> users;

    // A tenant has many SSO configurations
    @OneToMany(mappedBy = "tenant", cascade = CascadeType.ALL, orphanRemoval = true)
    private Set<SsoConfiguration> ssoConfigurations;

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getSubdomain() { return subdomain; }
    public void setSubdomain(String subdomain) { this.subdomain = subdomain; }
    public Set<User> getUsers() { return users; }
    public void setUsers(Set<User> users) { this.users = users; }
    public Set<SsoConfiguration> getSsoConfigurations() { return ssoConfigurations; }
    public void setSsoConfigurations(Set<SsoConfiguration> ssoConfigurations) { this.ssoConfigurations = ssoConfigurations; }
}