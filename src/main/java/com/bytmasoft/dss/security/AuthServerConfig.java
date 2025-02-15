package com.bytmasoft.dss.security;


import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;

import java.security.NoSuchAlgorithmException;
import java.util.UUID;

@RequiredArgsConstructor
@Configuration
public class AuthServerConfig {

private final KeyManager keyManager;

// OAuth2 Authorization Server endpoints configuration
@Bean
@Order(Ordered.HIGHEST_PRECEDENCE)
public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {

	OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
			OAuth2AuthorizationServerConfigurer.authorizationServer();

	http.with(authorizationServerConfigurer, Customizer.withDefaults());

	// Limit this chain only to endpoints starting with /oauth2/**
	http.securityMatcher("/oauth2/token/**")
			.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
			.csrf(csrf -> csrf.ignoringRequestMatchers("/oauth2/**"));

	return http.build();
}

// Default security configuration for non-OAuth2 endpoints
@Bean
@Order(Ordered.LOWEST_PRECEDENCE)
public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
	http.securityMatcher("/auth/**")
			.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
			//.oauth2Login( );
			.formLogin(Customizer.withDefaults());
	return http.build();
}


// Registered client configuration (here using authorization code grant)
@Bean
public RegisteredClientRepository registeredClientRepository() {
	RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
			                                    .clientId("client") // Client ID
			                                    .clientSecret(passwordEncoder().encode("secret")) // Use {noop} for plain text in demo; in production encode this
			                                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) // Authentication method
			                                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE) // Grant type
			                                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
			                                    // Add this line before building the registered client
			                                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
			                                    .authorizationGrantType(AuthorizationGrantType.PASSWORD)
			                                    .redirectUri("http://spring.io/auth")
			                                    .scope(OidcScopes.OPENID)
			                                    .scope("read") // Scopes
			                                    .scope("write")
			                                    .build();

	return new InMemoryRegisteredClientRepository(registeredClient);
}

/*@Bean
public AuthenticationManager authenticationManager(HttpSecurity http, DssUserDetailsService dssUserDetailsService) throws Exception {
	return http.getSharedObject(AuthenticationManagerBuilder.class)
			       .userDetailsService(dssUserDetailsService)
			       .passwordEncoder(passwordEncoder())

			       .build();

}*/

@Bean
public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
	return new ImmutableJWKSet<>(new JWKSet(keyManager.getRSAKey()));
}


// Use a secure password encoder (BCrypt)
@Bean
public PasswordEncoder passwordEncoder() {
	return new BCryptPasswordEncoder();
}


@Bean
public AuthorizationServerSettings authorizationServerSettings() {
	return AuthorizationServerSettings.builder()
			       .build();
}

}
