package gov.ca.emsa.pulse.auth.authentication;

import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.BadCredentialsException;

import gov.ca.emsa.pulse.auth.jwt.JWTCreationException;

public interface Authenticator {

	public String getJWT(String saml) throws JWTCreationException;
	public String refreshJWT() throws JWTCreationException;

}
