package gov.ca.emsa.pulse.auth.authentication;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import gov.ca.emsa.pulse.auth.jwt.JWTAuthor;
import gov.ca.emsa.pulse.auth.jwt.JWTConsumer;
import gov.ca.emsa.pulse.auth.jwt.JWTCreationException;

@Service
public class UserAuthenticator implements Authenticator {
	private static final Logger logger = LogManager.getLogger(UserAuthenticator.class);

	@Autowired
	private JWTAuthor jwtAuthor;

	@Autowired
	private JWTConsumer jwtConsumer;

	@Override
	public String refreshJWT(String oldJwt) throws JWTCreationException {
		String jwt = null;

        // Parse old Jwt
        Map<String, Object> claims = jwtConsumer.consume(oldJwt);
        List<String> authorityInfo = (List<String>) claims.get("Authorities");
        List<String> identityInfo = (List<String>) claims.get("Identity");
        Map<String, List<String>> jwtClaims = new HashMap<String, List<String>>();
        jwtClaims.put("Authorities", authorityInfo);
        jwtClaims.put("Identity", identityInfo);

        // Create new jwt
        jwt = jwtAuthor.createJWT(identityInfo.get(2), jwtClaims);

		return jwt;
	}

	public JWTAuthor getJwtAuthor() {
		return jwtAuthor;
	}

	public void setJwtAuthor(JWTAuthor jwtAuthor) {
		this.jwtAuthor = jwtAuthor;
	}

}
