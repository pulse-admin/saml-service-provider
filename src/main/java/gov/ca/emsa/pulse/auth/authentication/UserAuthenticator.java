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

//import gov.ca.emsa.pulse.auth.Util;
//import gov.ca.emsa.pulse.auth.dao.impl.InvitationDAOImpl;
//import gov.ca.emsa.pulse.auth.dto.UserDTO;
//import gov.ca.emsa.pulse.auth.dto.UserPermissionDTO;
import gov.ca.emsa.pulse.auth.jwt.JWTAuthor;
import gov.ca.emsa.pulse.auth.jwt.JWTCreationException;
//import gov.ca.emsa.pulse.auth.permission.GrantedPermission;
//import gov.ca.emsa.pulse.auth.user.User;
//import gov.ca.emsa.pulse.auth.user.UserManagementException;
//import gov.ca.emsa.pulse.auth.user.UserRetrievalException;

@Service
public class UserAuthenticator implements Authenticator {
	private static final Logger logger = LogManager.getLogger(UserAuthenticator.class);

	@Autowired
	private JWTAuthor jwtAuthor;

	public String getJWT(String saml) throws JWTCreationException {
		String jwt = null;
		Map<String, List<String>> claims = new HashMap<String, List<String>>();

		List<String> claimStrings = new ArrayList<String>();
        //		Set<UserPermissionDTO> permissions = getUserPermissions(user);

        claimStrings.add("login");
        /*		for (UserPermissionDTO claim : permissions){
			claimStrings.add(claim.getAuthority());
            }*/
		claims.put("Authorities", claimStrings);

		List<String> identity = new ArrayList<String>();

        identity.add(saml);

		claims.put("Identity", identity);

		jwt = jwtAuthor.createJWT(saml, claims);
		return jwt;
	}

	@Override
	public String refreshJWT() throws JWTCreationException {
        //		User user = Util.getCurrentUser();
		String jwt = null;
        /*

		if (user != null){

			Map<String, List<String>> claims = new HashMap<String, List<String>>();
			List<String> claimStrings = new ArrayList<String>();

			Set<GrantedPermission> permissions = user.getPermissions();

			for (GrantedPermission claim : permissions){
				claimStrings.add(claim.getAuthority());
			}
			claims.put("Authorities", claimStrings);

			List<String> identity = new ArrayList<String>();

			identity.add(user.getId().toString());
			identity.add(user.getName());
			identity.add(user.getFirstName());
			identity.add(user.getLastName());

			claims.put("Identity", identity);

			jwt = jwtAuthor.createJWT(user.getSubjectName(), claims);
		} else {
			throw new JWTCreationException("Cannot generate token for Anonymous user.");
            }*/
		return jwt;
	}

	public JWTAuthor getJwtAuthor() {
		return jwtAuthor;
	}

	public void setJwtAuthor(JWTAuthor jwtAuthor) {
		this.jwtAuthor = jwtAuthor;
	}

}
