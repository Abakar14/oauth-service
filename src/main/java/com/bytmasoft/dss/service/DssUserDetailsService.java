package com.bytmasoft.dss.service;




/*@Service
public class DssUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username){
        return userRepository.findByUsername(username)
                .map(DssUserDetails::new)
                .orElseThrow(() -> new UsernameNotFoundException("User with "+username+" not found"));

    }
}*/
