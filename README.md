# Spring Boot-based Service Provider using Spring Security SAML extension adapted for PULSE

====================

## Project Description

This project expands upon the sample Spring Boot SAML project made by Vincenzo De Notaris with customizations required for deployment in a PULSE environment.

## Configuration

```sh
$ git clone https://github.com/pulse-admin/saml-service-provider.git
$ cd saml-service-provider
$ cp src/main/resources/application.properties.template src/main/resources/application.properties
$ # change entityId & keyLocation to appropriate values
$ nano src/main/resources/application.properties
$ cp src/test/resources/environment.test.properties.template src/test/resources/environment.test.properties
$ # change keyLocation to appropriate value
$ nano src/test/resources/environment.test.properties
```

## Build & run

``./gradlew bootRun`` will compile, build, and run the application, by default on http://localhost:8080

## Dependencies

This project depends on the [PULSE Authentication Module](https://github.com/pulse-admin/api/tree/development/pulse/auth) for JWT authoring & consuming. That project must be compiled and installed before this project will compile.

====================

## References

### Spring Boot

Spring Boot makes it easy to create Spring-powered, production-grade applications and services with absolute minimum fuss. It takes an opinionated view of the Spring platform so that new and existing users can quickly get to the bits they need.

- **Website:** [http://projects.spring.io/spring-boot/](http://projects.spring.io/spring-boot/)

### Spring Security SAML Extension

Spring SAML Extension allows seamless inclusion of SAML 2.0 Service Provider capabilities in Spring applications. All products supporting SAML 2.0 in Identity Provider mode (e.g. ADFS 2.0, Shibboleth, OpenAM/OpenSSO, Ping Federate, Okta) can be used to connect with Spring SAML Extension.

- **Website:** [http://projects.spring.io/spring-security-saml/](http://projects.spring.io/spring-security-saml/)

---------

## Project description

Currently Spring Security SAML module doesn't provide a starter for Spring Boot. Moreover, its configuration is XML-based as of this writing. The aim of this project is to explain how to develop a **Service Provider (SP)** which uses **Spring Boot** (`1.3.0.RELEASE`) and **Spring Security SAML Extension** (`1.0.1.RELEASE`), by defining an annotation-based configuration (**Java Configuration**). **Thymeleaf** is also used as template engine.

**SSOCircle** ([ssocircle.com](http://www.ssocircle.com/en/portfolio/publicidp/)) is used as public Identity Provider for test purpose.

- **Author:** Vincenzo De Notaris ([dev@vdenotaris.com](mailto://dev@vdenotaris.com))
- **Website:** [vdenotaris.com](http://www.vdenotaris.com)
- **Version:**  ` 1.2.1.RELEASE `

Thanks to *Vladimír Schäfer* ([github.com/vschafer](https://github.com/vschafer)) for supporting my work.

### Unit tests

I would like to say thank you to *Alexey Syrtsev* ([github.com/airleks](https://github.com/airleks)) for his contribution on unit tests.

| Metric | Result |
| ------------- | -----:|
| Coverage % | 99% |
| Lines Covered | 196 |
| Total Lines | 199 |

### Setting up https on local machine
1. Make sure the following lines are in the application.properties of SSP, Broker, Mock, and Service
server.ssl.key-store: src/main/resources/keystore.p12
server.ssl.key-store-password: pulse123
server.ssl.keyStoreType: PKCS12
server.ssl.keyAlias: tomcat

2. Make sure all urls in application.properties files have prepend https and not http

3. Open gitbash as Administrator and cd into saml-service-provider src/main/resources/

4. Generate self-signed certificate 
	a. Excute command: keytool -genkey -alias tomcat -storetype PKCS12 -keyalg RSA -keysize 2048 -keystore keystore.p12 -validity 365
	b. Enter password 'pulse123'
	c. The first question will be: "What is your first and last name?" Enter: localhost
	d. Answer the next few questions, answers dont matter

5. Import self-signed certificate into the jvm's trust store
	a. Execute the command: keytool -exportcert -keystore keystore.p12 -storepass pulse123 -storetype PKCS12 -alias tomcat -file server.cer
	b. Execute the command: keytool -importcert -keystore $JAVA_HOME/jre/lib/security/cacerts -storepass changeit -alias tomcat -file server.cer
	c. Type yes when it asks if you want to trust this certificate

6. Copy the keystore.p12 file from the current directory to the src/main/resources/ directory of Mock, Broker, and Service
7. Re-run SSP, Broker, Mock and Service

### License

    Copyright 2016 Audacious Inquiry, LLC

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	    http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
