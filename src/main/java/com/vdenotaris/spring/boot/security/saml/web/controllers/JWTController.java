package com.vdenotaris.spring.boot.security.saml.web.controllers;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.xml.security.utils.Base64;
import org.opensaml.xml.ConfigurationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.base.Charsets;
import com.google.common.io.Resources;
import com.vdenotaris.spring.boot.security.saml.web.core.Util;

import gov.ca.emsa.pulse.auth.user.JWTAuthenticatedUser;
import gov.ca.emsa.pulse.auth.user.UserRetrievalException;
import gov.ca.emsa.pulse.auth.jwt.JWTAuthor;
import gov.ca.emsa.pulse.auth.jwt.JWTConsumer;

@RestController
public class JWTController {

	@Autowired
	private JWTAuthor jwtAuthor;

    @Autowired
	private JWTConsumer jwtConsumer;
    
    private Util util = new Util();
    
    @Autowired private ResourceLoader resourceLoader;
    
    //Logger
	private static final Logger LOG = LoggerFactory.getLogger(JWTController.class);
    private static final int JWT_INDEX = 8;
    private static final int JWT_ID = 1;
    
    public String getAssertion() throws IOException, ConfigurationException{
		Resource pdFile = resourceLoader.getResource("classpath:assertion.xml");
		return Resources.toString(pdFile.getURL(), Charsets.UTF_8);
	}

    @RequestMapping(value="/jwt", method= RequestMethod.GET,
                    produces="application/json; charset=utf-8")
	public String getJwt() throws IOException, ConfigurationException {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        JWTAuthenticatedUser user;
        if (principal.toString().equals("anonymousUser")) {
        	
            user = new JWTAuthenticatedUser();
            user.setuser_id("user_id");
            user.setSubjectName("username");
            user.setusername("username");
            user.setauth_source("auth_source");
            user.setfull_name("full_name");
            user.setorganization("organization");
            user.setpurpose_for_use("purpose_for_use");
            
            user.setrole("role");
            List<String> authorityInfo = new ArrayList<String>();
            List<String> identityInfo = new ArrayList<String>();
            authorityInfo.add("ROLE_USER");
            identityInfo.add(user.getuser_id());
            identityInfo.add(user.getUsername()); // JWT_ID location
            identityInfo.add(user.getauth_source());
            identityInfo.add(user.getfull_name());
            identityInfo.add(user.getorganization());
            identityInfo.add(user.getpurpose_for_use());
            identityInfo.add(user.getrole());

            Map<String, List<String>> jwtClaims = new HashMap<String, List<String>>();
            jwtClaims.put("Authorities", authorityInfo);
            jwtClaims.put("Identity", identityInfo);
            String jwt = jwtAuthor.createJWT(user.getSubjectName(), jwtClaims);
            user.setJwt(jwt);
            String pulseUserId = null;
            String jwtToReturn = null;
        	try {
				pulseUserId = util.createPulseUserWithAssertion(user, getAssertion());
				user.setPulseUserId(pulseUserId);
				identityInfo.add(user.getPulseUserId());
				jwtClaims.put("Identity", identityInfo);
				jwtToReturn = jwtAuthor.createJWT(user.getSubjectName(), jwtClaims);
				user.setJwt(jwtToReturn);
			} catch (JsonProcessingException | UserRetrievalException e) {
				e.printStackTrace();
			}
            LOG.info("Fake user: " + user.toString());
        } else {
            user = (JWTAuthenticatedUser) principal;
            LOG.info(user.toString() + " [Retrieving token: " + user.getJwt() + "]");
        }
        if (user != null && user.getJwt() != null) {
            String jwtJSON = "{\"token\": \""+ user.getJwt() +"\"}";
            return jwtJSON;
        } else {
            return "{\"token\": null}";
        }
	}

    @RequestMapping(value="/jwt/setAcf", method=RequestMethod.POST,
                    produces="application/json; charset=utf-8")
    public String setAcf(@RequestHeader(value="Authorization") String authorization, @RequestBody String acf) {
		String jwt = null;
        String oldJwt = authorization.split(" ")[1];

        // Parse old Jwt
        Map<String, Object> claims = jwtConsumer.consume(oldJwt);
        List<String> authorityInfo = (List<String>) claims.get("Authorities");
        List<String> identityInfo = (List<String>) claims.get("Identity");
        if (identityInfo.size() <= JWT_INDEX) {
            identityInfo.add(acf);
        } else {
            identityInfo.set(JWT_INDEX,acf);
        }
        Map<String, List<String>> jwtClaims = new HashMap<String, List<String>>();
        jwtClaims.put("Authorities", authorityInfo);
        jwtClaims.put("Identity", identityInfo);

        // Create new jwt
        jwt = jwtAuthor.createJWT(identityInfo.get(JWT_ID), jwtClaims);

        LOG.info("Setting acf: " + acf);

        String jwtJSON = "{\"token\": \""+ jwt +"\"}";

		return jwtJSON;
    }

    @RequestMapping(value="/jwt/keepalive", method=RequestMethod.POST,
    		produces="application/json; charset=utf-8")
    public String keepAlive(@RequestHeader(value="Authorization") String authorization, @RequestBody String acf) {
		String jwt = null;
        String oldJwt = authorization.split(" ")[1];

        // Parse old Jwt
        Map<String, Object> claims = jwtConsumer.consume(oldJwt);
        List<String> authorityInfo = (List<String>) claims.get("Authorities");
        List<String> identityInfo = (List<String>) claims.get("Identity");
        if (identityInfo.size() <= JWT_INDEX) {
            identityInfo.add(acf);
        } else {
        	identityInfo.remove(JWT_INDEX);
        	identityInfo.add(JWT_INDEX, acf);
        }
        Map<String, List<String>> jwtClaims = new HashMap<String, List<String>>();
        jwtClaims.put("Authorities", authorityInfo);
        jwtClaims.put("Identity", identityInfo);

        // Create new jwt
        jwt = jwtAuthor.createJWT(identityInfo.get(JWT_ID), jwtClaims);

        String jwtJSON = "{\"token\": \""+ jwt +"\"}";
		return jwtJSON;
    }
}
