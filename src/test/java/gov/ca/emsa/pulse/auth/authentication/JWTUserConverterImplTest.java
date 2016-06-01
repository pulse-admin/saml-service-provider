package gov.ca.emsa.pulse.auth.authentication;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import static org.junit.Assert.*;
import gov.ca.emsa.pulse.auth.jwt.JWTCreationException;
import gov.ca.emsa.pulse.auth.jwt.JWTValidationException;
import gov.ca.emsa.pulse.auth.jwt.JWTAuthorRsaJoseJImpl;
import gov.ca.emsa.pulse.auth.user.User;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = { gov.ca.emsa.pulse.auth.TestConfig.class })
public class JWTUserConverterImplTest {

	@Autowired
	private JWTUserConverterImpl converter;

	@Autowired
	private JWTAuthorRsaJoseJImpl jwtAuthor;

	// Logger
	private static final Logger LOG = LoggerFactory.getLogger(JWTUserConverterImplTest.class);

	@Test
	public void converterConvertsJWTToUser() throws JWTCreationException, JWTValidationException{

        String userId = "user";
        Map<String, List<String>> jwtAuthorities = new HashMap<String, List<String>>();
        jwtAuthorities.put("Authorities", new ArrayList<String>());
        jwtAuthorities.get("Authorities").add("ROLE_USER");
        jwtAuthorities.put("Identity", new ArrayList<String>());
        jwtAuthorities.get("Identity").add("First name");
        jwtAuthorities.get("Identity").add("Last name");
        jwtAuthorities.get("Identity").add("Email");

		String jwt = jwtAuthor.createJWT(userId, jwtAuthorities);
		User user = converter.getAuthenticatedUser(jwt);

        assertNotNull(user);

		assertEquals(user.getFirstName(), "First name");
		assertEquals(user.getLastName(), "Last name");
		//assertEquals(user.getSubjectName(), testUser.getSubjectName());
	}

	@Test
	public void converterConvertsRejectsInvalidStringForJWTToUser(){

		String garbage = "Garbage In";

		Boolean throwsException = false;

        try {
            User user = converter.getAuthenticatedUser(garbage);
		} catch (JWTValidationException e) {
            LOG.info("JWT Validation Exception", e);
            LOG.debug("JWT Validation Exception", e);
			throwsException = true;
		}
		assertTrue(throwsException);
	}
}
