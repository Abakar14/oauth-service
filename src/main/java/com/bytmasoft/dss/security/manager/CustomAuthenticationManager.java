package com.bytmasoft.dss.security.manager;

import com.bytmasoft.dss.service.DssUserDetailsService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Hier you can add your providers and check if it's supported
 */

//@Component
public class CustomAuthenticationManager implements AuthenticationManager {

private final DssUserDetailsService dssUserDetailsService;
private final PasswordEncoder passwordEncoder;
private final List<AuthenticationProvider> authenticationProviders;

CustomAuthenticationManager(DssUserDetailsService dssUserDetailsService, PasswordEncoder passwordEncoder, List<AuthenticationProvider> authenticationProviders){
	this.dssUserDetailsService = dssUserDetailsService;
	this.passwordEncoder = passwordEncoder;
	this.authenticationProviders = authenticationProviders;

}

@Override
public Authentication authenticate(Authentication authentication) throws AuthenticationException {
	// Only handle UsernamePasswordAuthenticationToken (user authentication)
	if (authentication instanceof UsernamePasswordAuthenticationToken) {
		UserDetails userDetails = dssUserDetailsService.loadUserByUsername(authentication.getName());
		if (passwordEncoder.matches(authentication.getCredentials().toString(), userDetails.getPassword())) {
			return new UsernamePasswordAuthenticationToken(userDetails, authentication.getCredentials(), userDetails.getAuthorities());
		}
		throw new BadCredentialsException("Invalid username or password");
	}
	// Return null for unsupported authentication types
	return null;
}

/*@Override
public Authentication authenticate(Authentication authentication) throws AuthenticationException {
	// Ensure this is a user authentication request
	if (authentication instanceof UsernamePasswordAuthenticationToken) {
		UserDetails userDetails = dssUserDetailsService.loadUserByUsername(authentication.getName());
		if (passwordEncoder.matches(authentication.getCredentials().toString(), userDetails.getPassword())) {
			return new UsernamePasswordAuthenticationToken(userDetails, authentication.getCredentials(), userDetails.getAuthorities());
		}
		throw new BadCredentialsException("Invalid username or password");
	}
	throw new AuthenticationException("Unsupported authentication type") {};
}*/

/*@Override
public Authentication authenticate(Authentication authentication) throws AuthenticationException {

	UserDetails userDetails = dssUserDetailsService.loadUserByUsername(authentication.getName());
	if(passwordEncoder.matches(authentication.getCredentials().toString(), userDetails.getPassword())){
		return new UsernamePasswordAuthenticationToken(userDetails, authentication.getCredentials(), userDetails.getAuthorities());
	}

	throw new BadCredentialsException("Invalid username or password");
	*//*for (AuthenticationProvider authenticationProvider : authenticationProviders) {
		if(authenticationProvider.supports(authentication.getClass())){
			return authenticationProvider.authenticate(authentication);
		}
	}
*//*
	//throw new AuthenticationException("No provider found for " + authentication.getClass().getName()) {};

}*/
}
