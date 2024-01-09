package painting;

import org.modelmapper.ModelMapper;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import painting.security.RsaKeyProperties;

@EnableConfigurationProperties(RsaKeyProperties.class)
@SpringBootApplication
public class PaintingOauth2Application {

	public static void main(String[] args) {
		SpringApplication.run(PaintingOauth2Application.class, args);
	}

	public ModelMapper modelMapper(){
		return new ModelMapper();
	}

}
