package gov.ca.emsa.pulse.auth.authentication;

import gov.ca.emsa.pulse.auth.jwt.JWTValidationException;
import gov.ca.emsa.pulse.auth.user.User;

public interface JWTUserConverter {

	//Check JWT and build a user given a JWT
	public User getAuthenticatedUser(String jwt) throws JWTValidationException;

}
