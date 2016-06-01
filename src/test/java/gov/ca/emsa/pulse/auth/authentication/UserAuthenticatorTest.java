package gov.ca.emsa.pulse.auth.authentication;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

import static org.junit.Assert.*;
import gov.ca.emsa.pulse.auth.jwt.JWTCreationException;
import gov.ca.emsa.pulse.auth.jwt.JWTValidationException;
import gov.ca.emsa.pulse.auth.jwt.JWTAuthorRsaJoseJImpl;
import gov.ca.emsa.pulse.auth.user.JWTAuthenticatedUser;
import gov.ca.emsa.pulse.auth.user.User;
import gov.ca.emsa.pulse.auth.user.UserRetrievalException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.support.DependencyInjectionTestExecutionListener;
import org.springframework.test.context.support.DirtiesContextTestExecutionListener;
import org.springframework.test.context.transaction.TransactionalTestExecutionListener;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = { gov.ca.emsa.pulse.auth.TestConfig.class })
@TestExecutionListeners({ DependencyInjectionTestExecutionListener.class,
    DirtiesContextTestExecutionListener.class,
    TransactionalTestExecutionListener.class
            })
public class UserAuthenticatorTest {

	@Autowired private Environment env;

	@Autowired
	private Authenticator authenticator;

	@Autowired
	private JWTAuthorRsaJoseJImpl jwtAuthor;

    @Test
	public void testRefreshJWT() throws JWTCreationException, JWTValidationException{

        String userId = "email";
        Map<String, List<String>> jwtClaims = new HashMap<String, List<String>>();
        jwtClaims.put("Authorities", new ArrayList<String>());
        jwtClaims.get("Authorities").add("ROLE_USER");
        jwtClaims.put("Identity", new ArrayList<String>());
        jwtClaims.get("Identity").add("First name");
        jwtClaims.get("Identity").add("Last name");
        jwtClaims.get("Identity").add("email");

		String oldJwt = jwtAuthor.createJWT(userId, jwtClaims);

		String jwt = authenticator.refreshJWT(oldJwt);
		assertNotNull(jwt);

        assertNotEquals(jwt, oldJwt);
	}
}
