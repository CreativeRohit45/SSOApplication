package com.example.demo.config;

import com.example.demo.model.Tenant;

public class TenantContext {

    private static final ThreadLocal<Tenant> currentTenant = new ThreadLocal<>();

    public static Tenant getCurrentTenant() {
        return currentTenant.get();
    }

    public static void setCurrentTenant(Tenant tenant) {
        currentTenant.set(tenant);
    }

    public static void clear() {
        currentTenant.remove();
    }
}