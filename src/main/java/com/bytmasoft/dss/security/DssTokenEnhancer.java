package com.bytmasoft.dss.security;

import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.stream.Collectors;

@Component
@Primary
public class DssTokenEnhancer implements OAuth2TokenCustomizer<JwtEncodingContext> {

@Override
public void customize(JwtEncodingContext context) {
	if (context.getPrincipal() instanceof UsernamePasswordAuthenticationToken) {
		UsernamePasswordAuthenticationToken authentication = (UsernamePasswordAuthenticationToken) context.getPrincipal();
		Set<String> authorities = authentication.getAuthorities().stream()
				                          .map(GrantedAuthority::getAuthority)
				                          .collect(Collectors.toSet());

		context.getClaims().claim("authorities", authorities);
	}
}
}
