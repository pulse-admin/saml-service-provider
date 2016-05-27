package gov.ca.emsa.pulse.auth.authentication;

import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.ca.emsa.pulse.auth.jwt.JWTConsumer;
import gov.ca.emsa.pulse.auth.jwt.JWTValidationException;
//import gov.ca.emsa.pulse.auth.permission.GrantedPermission;
import gov.ca.emsa.pulse.auth.user.JWTAuthenticatedUser;
import gov.ca.emsa.pulse.auth.user.User;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;


@Service
public class JWTUserConverterImpl implements JWTUserConverter {

	@Autowired
	private JWTConsumer jwtConsumer;

	private static final Logger LOG = LoggerFactory.getLogger(JWTUserConverterImpl.class);

	public JWTUserConverterImpl(){}

	public User getAuthenticatedUser(String jwt) throws JWTValidationException {

		JWTAuthenticatedUser user = new JWTAuthenticatedUser();
		user.setAuthenticated(true);

		Map<String, Object> validatedClaims = jwtConsumer.consume(jwt);

		if (validatedClaims == null){
			throw new JWTValidationException("Invalid authentication token.");
		} else {

			/*
			 * Handle the standard claim types. These won't be lists of Strings,
			 * which we'll be expecting from the claims we are creating ourselves
			 */
			Object issuer = validatedClaims.remove("iss");
			Object audience = validatedClaims.remove("aud");
			Object issuedAt = validatedClaims.remove("iat");
			Object notBefore = validatedClaims.remove("nbf");
			Object expires = validatedClaims.remove("exp");
			Object jti = validatedClaims.remove("jti");
			Object typ = validatedClaims.remove("typ");

			String subject = (String) validatedClaims.remove("sub");

            LOG.info(issuer.toString() + audience.toString() + issuedAt.toString() + notBefore.toString() + expires.toString() + jti.toString() + typ.toString());

			user.setSubjectName(subject);

			List<String> authorities = (List<String>) validatedClaims.get("Authorities");
			List<String> identityInfo = (List<String>) validatedClaims.get("Identity");

			for (String claim: authorities){
                //				GrantedPermission permission = new GrantedPermission(claim);
				user.addPermission(claim);
			}

			String idString = identityInfo.get(0);
			Long userId = Long.valueOf(idString);
			String firstName = identityInfo.get(2);
			String lastName = identityInfo.get(3);

			user.setId(userId);
			user.setFirstName(firstName);
			user.setLastName(lastName);

		}
		return user;
	}
}
