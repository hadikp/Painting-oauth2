package painting.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jwt.JwtEncoder;

import java.net.MalformedURLException;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class TokenServiceTest {


    JwtEncoder jwtEncoder;
    @Autowired
    RsaKeyProperties keyProperties;


    @Test
    void validateToken() throws MalformedURLException {
        TokenService tokenService = new TokenService(jwtEncoder, keyProperties);

        String token = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJzZWxmIiwic3ViIjoicGV0ZXIiLCJleHAiOjE3MDUxNjc1MzQsImlhdCI6MTcwNTE2NzQ3NCwic2NvcGUiOiJyZWFkIn0.TXLK1G_O6UJrKnkmsVvBjofKFE8ORNpzzzGNWg9tk_gvzepaDEuaMQByYXcivqYYV0j7pTNM_o0mDMU3Dh0i4AormUdGSd8IijER8OeyJ9jQxJqAW3VnD_HO0rG2wiH5NW1A7FZop6drGZ0EPxilzsq8t_YknZYAlZ8yGTgX9QsoR8o3vueSKB3po3c5PIL98ys4p-EMzo1UHHd8eMYhjm9QsDQTt21r961A8SK5T7HL5Cg34Zy0Ig8Pegr3OFchcozafWSDL7NhF_cHgcieZk9SyKt-bW2B-EVyu1PLzkN4JTeuKJ9I8w56gbqQ0W1Zg2fKU9O52f55L72B2qh-Cw";
        System.out.println("Token jó: " +tokenService.validateToken(token));
    }
}