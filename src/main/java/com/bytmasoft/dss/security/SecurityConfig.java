package com.bytmasoft.dss.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;


/**
 * This configuration handles application's general security
 * (for endpoints that are not part of the OAuth2 Authorization Server).
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {


@Bean
public SecurityFilterChain noOauthSecurityFilterChain(HttpSecurity http) throws Exception {
	 http
			 .authorizeHttpRequests(auth->
					                        auth.anyRequest().authenticated());

	http.formLogin(Customizer.withDefaults());

	return http.build();
}

}
