package se.iths.webservices.authservice.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

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

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateRsaKey() {

        KeyPair keyPair;

        try {

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();

        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }

        return keyPair;
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            if (context.getPrincipal() != null) {
                var authorities = context.getPrincipal().getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .filter(role -> role.startsWith("ROLE_")) // eller ta alla
                        .toList();
                context.getClaims().claim("roles", authorities);
            }
        };
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder encoder) {

//        RegisteredClient jokeserviceClient = RegisteredClient.withId(UUID.randomUUID().toString())
//                .clientId("jokeservice")
//                .clientSecret(encoder.encode("secret"))
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/jokeservice")
//                .scope(OidcScopes.OPENID)
//                .scope("scope-a")
//                .clientSettings(ClientSettings.builder()
//                        //.requireAuthorizationConsent(true)
//                        .build())
//                .build();

        RegisteredClient gatewayClient = RegisteredClient.withId("gateway-client")
                .clientId("gateway-client-id")
                .clientSecret(encoder.encode("gateway-client-secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://localhost:8080/login/oauth2/code/gateway-client")
                .scope(OidcScopes.OPENID)
                .scope("scope-a")
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        //.requireAuthorizationConsent(true)
                        .build())
                .build();

        return new InMemoryRegisteredClientRepository(gatewayClient);
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
}
