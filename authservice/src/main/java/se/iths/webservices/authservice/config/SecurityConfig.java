package se.iths.webservices.authservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

/*
The Order annotations are ordering the defined SecurityFilterChains to set different security configurations for different paths.
In the SecurityFilterChains there are securityMatchers that sets the chains authorization jurisdiction (paths),
the chain will apply its configurations to the matching paths and only to those.
This also means that if there is only one SecurityFilterChain defined with for example, a securityMatcher("/secure/**"),
all other endpoints are NOT secured by Spring Security. For that, there needs to be one more SecurityFilterChain without a defined securityMatcher.

The SecurityFilterChains MAY NOT collide, meaning that they may not configure the same paths (no point in different authentication setups for the same path).
The lower order chains may only configure paths that has not yet been configured.
The LOWEST order chain sets the configuration for all "left over" paths.

Endpoints Matcher: The getEndpointsMatcher() method ensures that the configuration applies only to the authorization server's endpoints.
 */

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // This configuration is only for authorization (jwt)
    @Bean
    @Order(1)
    SecurityFilterChain authorizationFilterChain(HttpSecurity http) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer.authorizationServer();

        http
                // set this securityFilterChain for the authorizationServer default endpoints
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, authserver -> authserver
                        .tokenRevocationEndpoint(Customizer.withDefaults())
                        .tokenIntrospectionEndpoint(Customizer.withDefaults())
                        .oidc(Customizer.withDefaults())
                )
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated()
                )
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                );

        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests(auth -> auth
                    .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults())
        ;

        return http.build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder encoder) {

        RegisteredClient client = RegisteredClient.withId("my-client")
                .clientId("my-client-id")
                .clientSecret(encoder.encode("my-client-secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://localhost:7000/login/oauth2/code/my-client")
                .scope(OidcScopes.OPENID)
                .scope("scope-a")
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .build())
                .build();

        return new InMemoryRegisteredClientRepository(client);
    }

    @Bean
    UserDetailsService userDetailsService(PasswordEncoder encoder) {
        UserDetails user = User.builder()
                .username("user")
                .password(encoder.encode("password"))
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

    /*
    AuthorizationServerSettings contains the configuration settings for the OAuth2 authorization server and is a REQUIRED component.
    It specifies the URI for the protocol endpoints as well as the issuer identifier. The default URI for the protocol endpoints are as follows:
    (If the issuer identifier is not configured in AuthorizationServerSettings.builder().issuer(String), it is resolved from the current request.)

			.authorizationEndpoint("/oauth2/authorize")
			.deviceAuthorizationEndpoint("/oauth2/device_authorization")
			.deviceVerificationEndpoint("/oauth2/device_verification")
			.tokenEndpoint("/oauth2/token")
			.tokenIntrospectionEndpoint("/oauth2/introspect")
			.tokenRevocationEndpoint("/oauth2/revoke")
			.jwkSetEndpoint("/oauth2/jwks")
			.oidcLogoutEndpoint("/connect/logout")
			.oidcUserInfoEndpoint("/userinfo")
			.oidcClientRegistrationEndpoint("/connect/register");
     */
//    @Bean
//    @Profile("!docker")
//    public AuthorizationServerSettings authorizationServerSettings() {
//        return AuthorizationServerSettings.builder()
//                .issuer("http://localhost:9000")
//                .build();
//    }

    // issuer for docker container
//    @Bean
//    @Profile("docker")
//    public AuthorizationServerSettings dockerAuthorizationServerSettings() {
//        return AuthorizationServerSettings.builder()
//                .issuer("http://auth:9000")
//                .build();
//    }
}
