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

import com.google.common.base.Charsets;
import com.google.common.io.Resources;
import com.vdenotaris.spring.boot.security.saml.web.CommonTestSupport;
import com.vdenotaris.spring.boot.security.saml.web.TestConfig;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.impl.AssertionMarshaller;
import org.opensaml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.signature.Signature;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import gov.ca.emsa.pulse.auth.permission.GrantedPermission;
import gov.ca.emsa.pulse.auth.user.JWTAuthenticatedUser;
import gov.ca.emsa.pulse.auth.user.UserRetrievalException;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes= {com.vdenotaris.spring.boot.security.saml.web.TestConfig.class})
public class SAMLUserDetailsServiceImplTest extends CommonTestSupport {
	
	public Assertion marshallAssertionObject() throws SAMLException, UnmarshallingException, ConfigurationException, XMLParserException{

		DefaultBootstrap.bootstrap(); 

		// Get parser pool manager
		BasicParserPool ppMgr = new BasicParserPool();
		ppMgr.setNamespaceAware(true);
		
		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
		
		SAMLObjectBuilder assertionBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
		
		
		Assertion assertion = (Assertion) assertionBuilder.buildObject();
		
		SAMLObjectBuilder issuerBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        Issuer issuer = (Issuer) issuerBuilder.buildObject();
        issuer.setValue("https://california.demo.collaborativefusion.com/sso/saml2/idp/");
        assertion.setIssuer(issuer);
        
        SAMLObjectBuilder subjectBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
        Subject subject = (Subject) subjectBuilder.buildObject();
        
        SAMLObjectBuilder subjectConfBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
        SubjectConfirmation subjConfirmation = (SubjectConfirmation) subjectConfBuilder.buildObject();
        subjConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer");
        subject.getSubjectConfirmations().add(subjConfirmation);
        
        assertion.setSubject(subject);
        
        XMLObjectBuilder<Signature> signatureBuilder = Configuration.getBuilderFactory().getBuilder(Signature.DEFAULT_ELEMENT_NAME);
        Signature signature = signatureBuilder.buildObject(Signature.DEFAULT_ELEMENT_NAME);
        
        assertion.setSignature(signature);
        
        return assertion;
	}
	
	@Autowired private ResourceLoader resourceLoader;
	
	public static String JWT = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJDQUxFTVNBIiwiYXVkIjoiQ0FMRU1TQSIsImV4cCI6MTQ5OTMwOTAzNiwianRpIjoiOC14WnZ3NDh6VEZsVFZRUDQ4ZE1oQSIsImlhdCI6MTQ5MzMwOTAzNiwibmJmIjoxNDkzMzA4Nzk2LCJzdWIiOiJVc2VyTmFtZSIsIkF1dGhvcml0aWVzIjpbIlJPTEVfVVNFUiJdLCJJZGVudGl0eSI6WyJ1c2VyX2lkIiwidXNlcm5hbWUiLCJhdXRoX3NvdXJjZSIsImZ1bGxfbmFtZSIsIm9yZ2FuaXphdGlvbiIsInB1cnBvc2VfZm9yX3VzZSIsInJvbGUiXX0.RUFS3DYbdbJuJnddby3X4WlpuCIDN1rnEhNlR396dz7SybOf51WHCLQEpVoj_gPfIXi4IKEwuU6_KV2u4R57NmFt28UkXy68fIgkonxhp0S1c_S06merPiIZaSGFOEo-yVmqb_YdsQILwUM6ppCiRgjHr5PSD3eDIiwcR3p0MsoVVuzgk6VPhgHZSEeI9wapDNiYC5c2xCyWUIHT7zgxH_r-YImJhosqhK0lju8RfqqOLb7VnBeY0pNwf746eQ1jKxoVNoUpzj4n7TtqcJL_vex1KvcRe2hPYgQqwDZB6l-Wj9uT0m9WxS42zaAlFkV552Wta0uh3VfO7SE2Mys17Q";

    @Autowired
    private SAMLUserDetailsServiceImpl userDetailsService;

    @Autowired
    Environment env;

    @Test
    public void testLoadUserBySAML() throws SAMLException, IOException, ConfigurationException, UnmarshallingException, XMLParserException, UserRetrievalException {
        // given
        NameID mockNameID = mock(NameID.class);
        when(mockNameID.getValue()).thenReturn(USER_NAME);
        
        SAMLCredential credentialsMock = mock(SAMLCredential.class);
        when(credentialsMock.getNameID()).thenReturn(mockNameID);
       
        Assertion assertion = marshallAssertionObject();
        when(credentialsMock.getAuthenticationAssertion()).thenReturn(assertion);
        
        Util util = mock(Util.class);
        JWTAuthenticatedUser jwtUser = new JWTAuthenticatedUser("UserName");
		jwtUser.addPermission("ROLE_USER");
		jwtUser.setJwt(JWT);
        when(util.createPulseUserWithAssertion(Mockito.anyObject(), Mockito.anyString())).thenReturn("1");
        
        // when
		userDetailsService.util = util;
        Object actual = userDetailsService.loadUserBySAML(credentialsMock);

        // / then
        assertNotNull(actual);
        assertTrue(actual instanceof JWTAuthenticatedUser);

        JWTAuthenticatedUser user = (JWTAuthenticatedUser)actual;
        assertEquals(USER_NAME, user.getSubjectName());
        assertEquals(1, user.getAuthorities().size());
        assertEquals(1, Integer.parseInt(user.getPulseUserId()));

        List<GrantedAuthority> authorities = new ArrayList<>(user.getAuthorities());
        Object authority = authorities.get(0);

        assertTrue(authority instanceof GrantedPermission);
        assertEquals(USER_ROLE, ((GrantedPermission)authority).getAuthority());
    }
    
    @Test
    public void testCreateSignature(){
    	Signature signature = userDetailsService.createSignature();
    	Assert.assertNotNull(signature);
    }
}
