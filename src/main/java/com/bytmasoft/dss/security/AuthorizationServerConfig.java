package com.bytmasoft.dss.security;

import com.bytmasoft.dss.entities.DssUserDetails;
import com.bytmasoft.dss.service.DssUserDetailsService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.UUID;

@RequiredArgsConstructor
@Configuration
public class AuthorizationServerConfig {

private final KeyManager keyManager;
private final PasswordEncoder passwordEncoder;




@Bean
@Order(Ordered.HIGHEST_PRECEDENCE)
public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

	OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
			OAuth2AuthorizationServerConfigurer.authorizationServer();
	http
			.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
			.with(authorizationServerConfigurer, (authorizationServer) ->
					                                     authorizationServer
							                                    // .registeredClientRepository(registeredClientRepository())
							                                    // .authorizationServerSettings(authorizationServerSettings())
							                                     .oidc(Customizer.withDefaults()))

			.exceptionHandling(exception -> {
				exception.defaultAuthenticationEntryPointFor(
						new LoginUrlAuthenticationEntryPoint("/login"),
						new MediaTypeRequestMatcher(MediaType.TEXT_HTML));
			});

	return http.build();
}


@Bean
public RegisteredClientRepository registeredClientRepository() {
	RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
			                                    .clientId("client") // Client ID
			                                    .clientSecret(passwordEncoder.encode("secret")) // Client Secret
			                                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) // Authentication method
			                                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE) // Grant type
			                                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
			                                    .redirectUri("http://localhost:8082")
			                                    .scope(OidcScopes.OPENID)
			                                    .tokenSettings(
														TokenSettings.builder()
																.accessTokenTimeToLive(Duration.ofHours(1))
																.build()
			                                    )

			                                   // .scope("read") // Scopes
			                                    //.scope("write")
			                                    .clientSettings(ClientSettings.builder().requireProofKey(false).build())
			                                    .build();

	return new InMemoryRegisteredClientRepository(registeredClient);
}


@Bean
public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
	return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
}

@Bean
public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
	//return new ImmutableJWKSet<>(new JWKSet(keyManager.getRSAKey()));
	JWKSet jwkSet = new JWKSet(keyManager.getRSAKey());
	return (jwkSelector, context) -> jwkSelector.select(jwkSet);
}




@Bean
public AuthorizationServerSettings authorizationServerSettings() {
	return AuthorizationServerSettings.builder()
			      .authorizationEndpoint("/oauth2/authorize")
			       .deviceAuthorizationEndpoint("/oauth2/device_authorization")
			       .deviceVerificationEndpoint("/oauth2/device_verification")
			       .tokenEndpoint("/oauth2/token")
			       .tokenIntrospectionEndpoint("/oauth2/introspect")
			       .tokenRevocationEndpoint("/oauth2/revoke")
			       .jwkSetEndpoint("/oauth2/jwks")
			       .oidcLogoutEndpoint("/connect/logout")
			       .oidcUserInfoEndpoint("/userinfo")
			       .oidcClientRegistrationEndpoint("/connect/register")
			       .build();
}


@Bean
UserDetailsService userDetailsService(){
	var user = User.withUsername("abakar")
			           .password(passwordEncoder.encode("123"))
			.roles("USER", "ADMIN")
			.build();
	return new InMemoryUserDetailsManager(user);
}

}
