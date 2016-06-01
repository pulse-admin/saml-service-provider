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

package gov.ca.emsa.pulse.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;

@SpringBootApplication(scanBasePackages= {"gov.ca.emsa.pulse.auth.**",
                                          "com.vdenotaris.spring.boot.security.saml.web.**"})
@PropertySource("classpath:/environment.test.properties")
public class TestConfig extends WebMvcConfigurerAdapter implements EnvironmentAware {
    private Environment env;

	// Logger
	private static final Logger LOG = LoggerFactory
			.getLogger(TestConfig.class);

    @Override
    public void setEnvironment(final Environment e) {
        this.env = e;
        LOG.info(env.getProperty("entityId"));
    }
}
