package com.vdenotaris.spring.boot.security.saml.web.core;

import gov.ca.emsa.pulse.auth.user.JWTAuthenticatedUser;
import gov.ca.emsa.pulse.auth.user.UserRetrievalException;
import gov.ca.emsa.pulse.common.domain.PulseUser;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class Util {
	
	//@Value("${serviceUrl")
	private String serviceUrl = "https://localhost:9090";
	
	public String createPulseUserWithAssertion(JWTAuthenticatedUser jwtUser, String assertion) throws JsonProcessingException, UserRetrievalException{
		RestTemplate query = new RestTemplate();
		MultiValueMap<String, String> headers = new LinkedMultiValueMap<String, String>();
		ObjectMapper mapper = new ObjectMapper();

		PulseUser toCreate = new PulseUser();
		toCreate.setAssertion(assertion);
		
		PulseUser returnUser = null;
		if(jwtUser == null){
			throw new UserRetrievalException("Could not find a logged in user. ");
		} else {
			headers.add("Authorization","Bearer " + jwtUser.getJwt());
			HttpEntity<PulseUser> request = new HttpEntity<PulseUser>(toCreate, headers);
			returnUser = query.postForObject(serviceUrl + "/user/create", request, PulseUser.class);
		}
		return String.valueOf(returnUser.getId());
	}
}
