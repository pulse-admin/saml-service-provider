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

import java.io.IOException;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.impl.AssertionMarshaller;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.security.saml.util.SAMLUtil;
import org.springframework.stereotype.Service;
import org.w3c.dom.Element;

import com.google.common.base.Charsets;
import com.google.common.io.Resources;

import gov.ca.emsa.pulse.auth.permission.GrantedPermission;
import gov.ca.emsa.pulse.auth.user.JWTAuthenticatedUser;
import gov.ca.emsa.pulse.auth.jwt.JWTAuthorRsaJoseJImpl;

@Service
public class SAMLUserDetailsServiceImpl implements SAMLUserDetailsService {

	// Logger
	private static final Logger LOG = LoggerFactory.getLogger(SAMLUserDetailsServiceImpl.class);

    @Autowired
    JWTAuthorRsaJoseJImpl jwtAuthor;
    @Autowired private ResourceLoader resourceLoader;
    
    public String getAssertion() throws IOException, ConfigurationException{
		Resource pdFile = resourceLoader.getResource("classpath:assertion.xml");
		return Resources.toString(pdFile.getURL(), Charsets.UTF_8);
	}

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
	    Assertion assertion = credential.getAuthenticationAssertion();
	    AssertionMarshaller am = new AssertionMarshaller();
	    Element assertionElement = null;
		try {
			assertionElement = am.marshall(assertion);
		} catch (MarshallingException e) {
			e.printStackTrace();
		}
		
		StringWriter sr = new StringWriter();
		try {
			TransformerFactory.newInstance().newTransformer().transform(new DOMSource(assertionElement), new StreamResult(sr));
		} catch (TransformerException | TransformerFactoryConfigurationError e) {
			e.printStackTrace();
		}
		String assertionString = sr.getBuffer().toString();
        Map<String, List<String>> jwtClaims = new HashMap<String, List<String>>();
        jwtClaims.put("Authorities", new ArrayList<String>());
        jwtClaims.get("Authorities").add("ROLE_USER");
        jwtClaims.put("Identity", new ArrayList<String>());
        if (credential.getAttribute("auth_source") != null && credential.getAttributeAsString("auth_source").equals("DHV")) {
            jwtClaims.get("Identity").add(credential.getAttributeAsString("uid"));
            jwtClaims.get("Identity").add(credential.getAttributeAsString("username"));
            jwtClaims.get("Identity").add(credential.getAttributeAsString("auth_source"));
            jwtClaims.get("Identity").add(credential.getAttributeAsString("full_name"));
            jwtClaims.get("Identity").add(credential.getAttributeAsString("organization"));
            jwtClaims.get("Identity").add(credential.getAttributeAsString("purpose_for_use"));
            jwtClaims.get("Identity").add(credential.getAttributeAsString("role"));
            jwtClaims.get("Identity").add(assertionString);
        } else {
            jwtClaims.get("Identity").add("user_id");
            jwtClaims.get("Identity").add("username");
            jwtClaims.get("Identity").add("auth_source");
            jwtClaims.get("Identity").add("full_name");
            jwtClaims.get("Identity").add("organization");
            jwtClaims.get("Identity").add("purpose_for_use");
            jwtClaims.get("Identity").add("role");
            try {
				jwtClaims.get("Identity").add(getAssertion());
			} catch (IOException e1) {
				e1.printStackTrace();
			} catch (ConfigurationException e1) {
				e1.printStackTrace();
			}
            try {
				jwtClaims.get("Identity").add(getAssertion());
			} catch (IOException e) {
				e.printStackTrace();
			} catch (ConfigurationException e) {
				e.printStackTrace();
			}
        }
        String jwt = jwtAuthor.createJWT(userID, jwtClaims);
        JWTAuthenticatedUser user = new JWTAuthenticatedUser(userID);
        
        user.setuser_id(credential.getAttributeAsString("uid"));
        user.setusername(credential.getAttributeAsString("username"));
        user.setauth_source(credential.getAttributeAsString("auth_source"));
        user.setfull_name(credential.getAttributeAsString("full_name"));
        user.setorganization(credential.getAttributeAsString("organization"));
        user.setpurpose_for_use(credential.getAttributeAsString("purpose_for_use"));
        user.setrole(credential.getAttributeAsString("role"));
        user.setAssertion(assertionString);
        user.addPermission("ROLE_USER");
        user.setJwt(jwt);

        LOG.info("User is " + user.toString());
        return user;
	}
}
