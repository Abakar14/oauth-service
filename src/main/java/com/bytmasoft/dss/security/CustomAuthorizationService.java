package com.bytmasoft.dss.security;

import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthorizationService implements OAuth2AuthorizationService {

@Override
public void save(OAuth2Authorization authorization) {

}

@Override
public void remove(OAuth2Authorization authorization) {

}

@Override
public OAuth2Authorization findById(String id) {
	return null;
}

@Override
public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
	return null;
}
}
