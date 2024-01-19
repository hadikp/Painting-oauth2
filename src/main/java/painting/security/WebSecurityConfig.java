package painting.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    private final RsaKeyProperties rsaKeys;

    private JwtAuthEntryPoint jwtAuthEntryPoint;

    public WebSecurityConfig(RsaKeyProperties rsaKeys, JwtAuthEntryPoint jwtAuthEntryPoint) {
        this.rsaKeys = rsaKeys;
        this.jwtAuthEntryPoint = jwtAuthEntryPoint;
    }

    @Bean
    public InMemoryUserDetailsManager user(){
        return new InMemoryUserDetailsManager(User.withUsername("peter").password("{noop}password").authorities("read").build());
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        return http.csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth ->auth.requestMatchers("/api/admin").hasAuthority("ADMIN")
                                                   .requestMatchers("/").permitAll()
                                                   .anyRequest().authenticated())
                .oauth2ResourceServer(conf -> conf.jwt(withDefaults()))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) //disable session
                .exceptionHandling(configurer -> configurer.authenticationEntryPoint(WebSecurityConfig::handleException))
                .httpBasic(security -> security.authenticationEntryPoint(jwtAuthEntryPoint))
                .build();
    }

    private static void handleException(HttpServletRequest req, HttpServletResponse resp, AuthenticationException e) throws IOException {
        PrintWriter writer = resp.getWriter();
        writer.println(new ObjectMapper().writeValueAsString(new AuthorizationResponse("error", "Unauthorized")));
        resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public JwtDecoder jwtDecoder(){
        final NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(rsaKeys.publicKey()).build();
        decoder.setJwtValidator(tokenValidator());
        return decoder;
    }


    @Bean
    public OAuth2TokenValidator<Jwt> tokenValidator() {
        final List<OAuth2TokenValidator<Jwt>> validators = List.of(
                new JwtTimestampValidator(),
                new JwtIssuerValidator("https://c2id.com"));
        return new DelegatingOAuth2TokenValidator<Jwt>(validators);
    }

    @Bean
    public JwtEncoder jwtEncoder(){
        JWK jwk = new RSAKey.Builder(rsaKeys.publicKey()).privateKey(rsaKeys.privateKey()).build();
        JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwks);
    }

    private class JwtClaimSetVerifier {
    }
}
