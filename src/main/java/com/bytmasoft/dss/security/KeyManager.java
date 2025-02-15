package com.bytmasoft.dss.security;

import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import com.nimbusds.jose.jwk.RSAKey;

@Component
public class KeyManager {

private KeyPair keyPair;
private RSAKey rsaKey;

@PostConstruct
public void init() {
	try {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048); // Use a secure key size
		this.keyPair = keyPairGenerator.generateKeyPair();
		this.rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
				              .privateKey((RSAPrivateKey) keyPair.getPrivate())
				              .build();
	} catch (NoSuchAlgorithmException e) {
		throw new IllegalStateException("Failed to generate RSA key pair", e);
	}


}

public KeyPair getKeyPair() {
	return keyPair;
}

public RSAKey getRSAKey() throws NoSuchAlgorithmException {
		return rsaKey;
}

}
