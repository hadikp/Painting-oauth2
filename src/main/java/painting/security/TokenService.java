package painting.security;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.HashSet;
import java.util.stream.Collectors;

@Service
public class TokenService {

    private final JwtEncoder jwtEncoder;
    private RsaKeyProperties keyProperties;

    public TokenService(JwtEncoder jwtEncoder, RsaKeyProperties keyProperties) {
        this.jwtEncoder = jwtEncoder;
        this.keyProperties = keyProperties;
    }

    public String generateToken(Authentication authentication){
        Instant now = Instant.now();
        String scope = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(" "));
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("https://c2id.com")
                .issuedAt(now)
                .expiresAt(now.plus(1, ChronoUnit.MINUTES))
                .subject(authentication.getName())
                .claim("scope", scope) //user, admin
                .build();
        return this.jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    public Boolean validateToken(String token) throws MalformedURLException { //This is nimbus own validator with JWTClaimsSet (not with JwtClaimsSet)
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        //jwtProcessor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("at+jwt")));

        JWKSource<SecurityContext> keySource = JWKSourceBuilder
                .create(new URL("https://demo.c2id.com/jwks.json"))
                .retrying(true).build();
        JWSAlgorithm expectedJWSAAlg = JWSAlgorithm.RS256;

        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(
                expectedJWSAAlg,
                keySource);
        jwtProcessor.setJWSKeySelector(keySelector);

        jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                new JWTClaimsSet.Builder().issuer("https://demo.c2id.com").build(),
                new HashSet<>(Arrays.asList(
                        JWTClaimNames.SUBJECT,
                        JWTClaimNames.ISSUED_AT,
                        JWTClaimNames.EXPIRATION_TIME, "scp", "cid",
                        JWTClaimNames.JWT_ID))
        ));
        SecurityContext ctx = null;
        JWTClaimsSet claimsSet;
        try {
            claimsSet = jwtProcessor.process(token, ctx);
            System.out.println(claimsSet.toJSONObject());
            return true;
        } catch (ParseException | JOSEException e) {
            return false;
        } catch (BadJOSEException e) {
            throw new RuntimeException(e);
        }
    }
}
