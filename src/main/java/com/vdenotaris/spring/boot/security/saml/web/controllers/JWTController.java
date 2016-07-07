package com.vdenotaris.spring.boot.security.saml.web.controllers;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import gov.ca.emsa.pulse.auth.user.JWTAuthenticatedUser;
import gov.ca.emsa.pulse.auth.jwt.JWTAuthor;
import gov.ca.emsa.pulse.auth.jwt.JWTConsumer;

@RestController
public class JWTController {

	@Autowired
	private JWTAuthor jwtAuthor;

    @Autowired
	private JWTConsumer jwtConsumer;

    //Logger
	private static final Logger LOG = LoggerFactory.getLogger(JWTController.class);

    @RequestMapping(value="/jwt", method= RequestMethod.GET,
                    produces="application/json; charset=utf-8")
	public String getJwt() {
        JWTAuthenticatedUser user = (JWTAuthenticatedUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        LOG.info("Retrieving token: " + user.getJwt());
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
        if (identityInfo.size() <= 3) {
            identityInfo.add(acf);
        } else {
            identityInfo.set(3,acf);
        }
        Map<String, List<String>> jwtClaims = new HashMap<String, List<String>>();
        jwtClaims.put("Authorities", authorityInfo);
        jwtClaims.put("Identity", identityInfo);

        // Create new jwt
        jwt = jwtAuthor.createJWT(identityInfo.get(2), jwtClaims);

        LOG.info("Setting acf: " + acf);

        String jwtJSON = "{\"token\": \""+ jwt +"\"}";

		return jwtJSON;
    }
}
