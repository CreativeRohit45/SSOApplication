package com.example.demo.service;

import com.example.demo.config.TenantContext;
import com.example.demo.model.Tenant;
import com.example.demo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class JpaUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

        Tenant tenant = TenantContext.getCurrentTenant();

        if (tenant != null) {
            // This is a tenant login (rohit45.localhost)
            return userRepository.findByEmailAndTenant(email, tenant)
                    .orElseThrow(() ->
                            new UsernameNotFoundException("User " + email + " not found for this tenant."));
        } else {
            // This is a super-admin login (localhost)
            return userRepository.findByEmailAndTenantIsNull(email)
                    .orElseThrow(() ->
                            new UsernameNotFoundException("Super Admin " + email + " not found."));
        }
    }
}