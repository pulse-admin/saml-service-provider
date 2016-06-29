/*
 * Copyright 2016 Vincenzo De Notaris
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.vdenotaris.spring.boot.security.saml.web.core;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.beans.factory.annotation.Autowired;
import org.opensaml.saml2.core.Attribute;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.stereotype.Service;

import gov.ca.emsa.pulse.auth.permission.GrantedPermission;
import gov.ca.emsa.pulse.auth.user.JWTAuthenticatedUser;
import gov.ca.emsa.pulse.auth.jwt.JWTAuthorRsaJoseJImpl;

@Service
public class SAMLUserDetailsServiceImpl implements SAMLUserDetailsService {

	// Logger
	private static final Logger LOG = LoggerFactory.getLogger(SAMLUserDetailsServiceImpl.class);

    @Autowired
    JWTAuthorRsaJoseJImpl jwtAuthor;

	public Object loadUserBySAML(SAMLCredential credential)
			throws UsernameNotFoundException {

		// The method is supposed to identify local account of user referenced by
		// data in the SAML assertion and return UserDetails object describing the user.

		String userID = credential.getNameID().getValue();

		LOG.info(userID + " is logged in");
	    for (Attribute att : credential.getAttributes())
	    {
            LOG.info(att.getName() + ": " + credential.getAttributeAsString(att.getName()));
	    }

        Map<String, List<String>> jwtClaims = new HashMap<String, List<String>>();
        jwtClaims.put("Authorities", new ArrayList<String>());
        jwtClaims.get("Authorities").add("ROLE_USER");
        jwtClaims.put("Identity", new ArrayList<String>());
        if (credential.getAttribute("FirstName") != null) {
            jwtClaims.get("Identity").add(credential.getAttributeAsString("FirstName"));
            jwtClaims.get("Identity").add(credential.getAttributeAsString("LastName"));
            jwtClaims.get("Identity").add(credential.getAttributeAsString("EmailAddress"));
        } else if (credential.getAttribute("urn:oid:2.5.4.42") != null) {
            jwtClaims.get("Identity").add(credential.getAttributeAsString("urn:oid:2.5.4.42"));
            jwtClaims.get("Identity").add(credential.getAttributeAsString("urn:oid:2.5.4.4"));
            jwtClaims.get("Identity").add(credential.getAttributeAsString("urn:oid:1.3.6.1.4.1.5923.1.1.1.6"));
        } else {
            jwtClaims.get("Identity").add("FirstName");
            jwtClaims.get("Identity").add("LastName");
            jwtClaims.get("Identity").add("EmailAddress");
        }

        String jwt = jwtAuthor.createJWT(userID, jwtClaims);
        LOG.info("JWT is " + jwt);

		// In a real scenario, this implementation has to locate user in a arbitrary
		// dataStore based on information present in the SAMLCredential and
		// returns such a date in a form of application specific UserDetails object.
		//return new User(userID, "<abc123>", true, true, true, true, authorities);
        JWTAuthenticatedUser user = new JWTAuthenticatedUser(userID);
        user.setFirstName(credential.getAttributeAsString("FirstName"));
        user.setLastName(credential.getAttributeAsString("LastName"));
        user.setEmail(credential.getAttributeAsString("Email"));
        user.addPermission("ROLE_USER");
        user.setJwt(jwt);
        return user;
	}

}
