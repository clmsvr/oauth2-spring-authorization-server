package auth;

import java.util.TimeZone;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import auth.util.Base64ProtocolResolverApp;

@SpringBootApplication
public class AuthApplication {

	public static void main(String[] args) {
		
		//11.7
		TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
		
		//23.46 - adicionando um ApplicationListener para o protocolo de recurso "base64:"
		var app = new SpringApplication(AuthApplication.class);
		app.addListeners(new Base64ProtocolResolverApp());
		app.run(args);
		
		//SpringApplication.run(AuthApplication.class, args);
	}

}
