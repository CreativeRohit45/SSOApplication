package com.example.demo.repository;

import com.example.demo.model.Role;
import com.example.demo.model.Tenant;
import com.example.demo.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);
    Optional<User> findByEmailAndTenant(String email, Tenant tenant);
    Optional<User> findByEmailAndTenantIsNull(String email);
    List<User> findByTenant(Tenant tenant);
    List<User> findByRole(Role role);
    List<User> findByTenantAndRole(Tenant tenant, Role role);
}