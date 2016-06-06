package com.vdenotaris.spring.boot.security.saml.web.controllers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.vdenotaris.spring.boot.security.saml.web.stereotypes.CurrentUser;
import gov.ca.emsa.pulse.auth.user.JWTAuthenticatedUser;

@RestController
public class JWTController {

    //Logger
	private static final Logger LOG = LoggerFactory.getLogger(JWTController.class);

    @RequestMapping(value="/jwt", method= RequestMethod.GET,
                    produces="application/json; charset=utf-8")
	public String getJwt() {
        LOG.info(SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
        JWTAuthenticatedUser user = (JWTAuthenticatedUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        LOG.info(user.getJwt());
        if (user != null && user.getJwt() != null) {
            String jwtJSON = "{\"token\": \""+user.getJwt()+"\"}";
            return jwtJSON;
        } else {
            return "{\"token\": null}";
        }
	}
}
