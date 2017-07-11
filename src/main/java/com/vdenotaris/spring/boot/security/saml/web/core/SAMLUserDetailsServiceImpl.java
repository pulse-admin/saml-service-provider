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
import java.security.cert.X509Certificate;
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
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpEntity;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.impl.AssertionMarshaller;
import org.opensaml.saml2.core.impl.KeyInfoConfirmationDataTypeBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationDataBuilder;
import org.opensaml.saml2.core.KeyInfoConfirmationDataType;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.security.saml.util.SAMLUtil;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Charsets;
import com.google.common.io.Resources;
import com.vdenotaris.spring.boot.security.saml.web.config.WebSecurityConfig;

import gov.ca.emsa.pulse.auth.permission.GrantedPermission;
import gov.ca.emsa.pulse.auth.user.JWTAuthenticatedUser;
import gov.ca.emsa.pulse.auth.user.UserRetrievalException;
import gov.ca.emsa.pulse.auth.jwt.JWTAuthorRsaJoseJImpl;
import gov.ca.emsa.pulse.common.domain.PulseUser;

@Service
public class SAMLUserDetailsServiceImpl implements SAMLUserDetailsService {

	// Logger
	private static final Logger LOG = LoggerFactory.getLogger(SAMLUserDetailsServiceImpl.class);

	@Autowired
	JWTAuthorRsaJoseJImpl jwtAuthor;
	@Autowired private ResourceLoader resourceLoader;

	Util util = new Util();
	
	@Autowired Environment env;
	
	@Autowired private KeyManager keyManager;
	
	XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
	
	public String getAssertionFromFile() throws IOException, ConfigurationException{
		Resource pdFile = resourceLoader.getResource("classpath:assertion.xml");
		return Resources.toString(pdFile.getURL(), Charsets.UTF_8);
	}
	
	public Signature createSignature(){
		String alias = env.getProperty("keystoreUsername");
		Credential signingCredential = keyManager.getCredential(alias);
		
		SignatureBuilder signatureBuilder = (SignatureBuilder) builderFactory
				.getBuilder(Signature.DEFAULT_ELEMENT_NAME);
		Signature assertionSignature = signatureBuilder.buildObject(Signature.DEFAULT_ELEMENT_NAME);

		assertionSignature.setSigningCredential(signingCredential);
		assertionSignature
		.setCanonicalizationAlgorithm(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		assertionSignature
		.setSignatureAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1);

		X509KeyInfoGeneratorFactory kiFactory = new X509KeyInfoGeneratorFactory();
		kiFactory.setEmitEntityCertificate(true);

		KeyInfo keyInfo = null;
		try {
			keyInfo = kiFactory.newInstance().generate(signingCredential);
		} catch (SecurityException e) {
			LOG.error(e.getMessage());
		}

		assertionSignature.setKeyInfo(keyInfo);
		return assertionSignature;
	}
	
	public KeyInfoConfirmationDataType createSubjectConfirmationData(SubjectConfirmationData oldSubjConf, KeyInfo keyInfo){
		KeyInfoConfirmationDataTypeBuilder subjConfBuilder = (KeyInfoConfirmationDataTypeBuilder) builderFactory.getBuilder(KeyInfoConfirmationDataType.TYPE_NAME);
		KeyInfoConfirmationDataType subjConfData = subjConfBuilder.buildObject(KeyInfoConfirmationDataType.DEFAULT_ELEMENT_NAME);
		
		if(oldSubjConf.getInResponseTo() != null){
			subjConfData.setInResponseTo(oldSubjConf.getInResponseTo());
		}
		if(oldSubjConf.getNotOnOrAfter() != null){
			subjConfData.setNotOnOrAfter(oldSubjConf.getNotOnOrAfter());
		}
		if(oldSubjConf.getRecipient() != null){
			subjConfData.setRecipient(oldSubjConf.getRecipient());
		}
		
		subjConfData.getKeyInfos().add(keyInfo);
		
		return subjConfData;
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
		String assertionString = null;
		try {
			Assertion assertion = credential.getAuthenticationAssertion();
			assertion.getSubject().getSubjectConfirmations().get(0).setMethod("urn:oasis:names:tc:SAML:2.0:cm:holder-of-key");
			Signature sig = createSignature();
			assertion.setSignature(sig);
			Element assertionElement = SAMLUtil.marshallMessage(assertion);
			Node node = SAMLUtil.marshallMessage(sig.getKeyInfo());
			Node firstDocImportedNode = assertionElement.getOwnerDocument().importNode(node, true);
			NodeList nodeList = assertionElement.getElementsByTagName("*");
			for(int i=0; i < nodeList.getLength(); i++){
				Node nodeItem = nodeList.item(i);
				if(nodeItem.getLocalName().equals("SubjectConfirmationData")){
					nodeItem.appendChild(firstDocImportedNode);
				}
			}
			try {
				Configuration.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
			} catch (MarshallingException e) {
				e.printStackTrace();
			}
			try {
				Signer.signObject(sig);
			} catch (SignatureException e) {
				e.printStackTrace();
			}
			assertionString = XMLHelper.nodeToString(SAMLUtil.marshallMessage(assertion));
			System.out.println("Assertion String:" + assertionString);
		} catch (MessageEncodingException e1) {
			LOG.info(e1.getMessage());
		}

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
		} else {
			jwtClaims.get("Identity").add("user_id");
			jwtClaims.get("Identity").add("username");
			jwtClaims.get("Identity").add("auth_source");
			jwtClaims.get("Identity").add("full_name");
			jwtClaims.get("Identity").add("organization");
			jwtClaims.get("Identity").add("purpose_for_use");
			jwtClaims.get("Identity").add("role");
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
		user.addPermission("ROLE_USER");
		user.setJwt(jwt);

		String pulseUserId = null;
		if (credential.getAttribute("auth_source") != null && credential.getAttributeAsString("auth_source").equals("DHV")) {
			try {
				pulseUserId = util.createPulseUserWithAssertion(user, assertionString);
				jwtClaims.get("Identity").add(pulseUserId);
			} catch (JsonProcessingException | UserRetrievalException e) {
				e.printStackTrace();
			}
		}else{
			try {
				pulseUserId = util.createPulseUserWithAssertion(user, getAssertionFromFile());
				jwtClaims.get("Identity").add(pulseUserId);
			} catch (UserRetrievalException | IOException
					| ConfigurationException e) {
				e.printStackTrace();
			}
		}
		String jwtWithPulseUserId = jwtAuthor.createJWT(userID, jwtClaims);
		JWTAuthenticatedUser userWithPulseUserId = new JWTAuthenticatedUser(userID);
		userWithPulseUserId.setuser_id(credential.getAttributeAsString("uid"));
		userWithPulseUserId.setusername(credential.getAttributeAsString("username"));
		userWithPulseUserId.setauth_source(credential.getAttributeAsString("auth_source"));
		userWithPulseUserId.setfull_name(credential.getAttributeAsString("full_name"));
		userWithPulseUserId.setorganization(credential.getAttributeAsString("organization"));
		userWithPulseUserId.setpurpose_for_use(credential.getAttributeAsString("purpose_for_use"));
		userWithPulseUserId.setrole(credential.getAttributeAsString("role"));
		userWithPulseUserId.setPulseUserId(pulseUserId);
		userWithPulseUserId.addPermission("ROLE_USER");
		userWithPulseUserId.setJwt(jwtWithPulseUserId);

		LOG.info("User is " + user.toString());
		return userWithPulseUserId;
	}
}
