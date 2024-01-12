package painting.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jwt.JwtEncoder;

import java.security.interfaces.RSAPublicKey;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class TokenServiceTest {


    JwtEncoder jwtEncoder;
    @Autowired
    RsaKeyProperties keyProperties;


    @Test
    void validateToken() {
        TokenService tokenService = new TokenService(jwtEncoder, keyProperties);

        String token = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJzZWxmIiwic3ViIjoicGV0ZXIiLCJleHAiOjE3MDUwOTI0MDksImlhdCI6MTcwNTA5MjM0OSwic2NvcGUiOiJyZWFkIn0.r01DtS5P09BWOEOfRtm6TjZT-1x1Kl_5_ZF0BeWXinw3lM8LEN7Pg5zfQwbTGO8elsxdzfQ0M8s8o5u15_ToyzLitd6kBpK4B-RFqH3VgFmgYTSbhJz3XOPGioWgGTjXIjBIvllcqL-m6gedPY9Q6zd-w0ciuR7kpDJU_xsAdY5oi_xFXP2fU-NCelybDvedS5mvT10aCo_B_eVDePnUSNXTqxRO4Y9d4QeVopbz01AA9kmRLb7wPs-eaSmEzJ8WPrXIruH227pR6wMAPMdAjNdj5TSUHSPFdzEwgNdr792fp5e6kywI83-ztJg2EYdVn4DmmM0cp1yTMjKY7NZgWg";
        System.out.println("Token jó: " +tokenService.validateToken(token));
    }
}