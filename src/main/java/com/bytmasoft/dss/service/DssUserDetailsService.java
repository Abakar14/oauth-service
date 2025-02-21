package com.bytmasoft.dss.service;


import com.bytmasoft.dss.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import com.bytmasoft.dss.entities.DssUserDetails;
@RequiredArgsConstructor
//@Service
public class DssUserDetailsService implements UserDetailsService {


    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username){
        return userRepository.findByUsername(username)
                .map(DssUserDetails::new)
                .orElseThrow(() -> new UsernameNotFoundException("User with "+username+" not found"));

    }
}
