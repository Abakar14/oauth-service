package com.bytmasoft.dss.entities;

import lombok.extern.java.Log;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;

@Log
public class DssUserDetails implements UserDetails {

    private User user;

    public DssUserDetails(User user) {
        this.user = user;
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

     Role role = user.getRole();
        List<GrantedAuthority> authorities = new ArrayList<>();
     while (role != null) {
         Set<Permission> permissions = role.getPermissions();
         for (Permission permission : permissions) {
             authorities.add(new SimpleGrantedAuthority(permission.getName()));
         }
         role = role.getParentRole();

     }
        return authorities;
    }


    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
    return true;
    }
}
