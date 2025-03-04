package auth.util;

import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.ProtocolResolver;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import java.util.Base64;


//23.46 
//Esta Solução NAO necessita de alterar a classe da Aplicação do Spring: AuthApplication
//MAS PRECISA do arquivo "spring.factories" criado em "src/main/resources/META-INF"

/**
Para carregar essa classe e suas configurações antes mesmo da aplicação inciar, 
crie um arquivo chamado :

   spring.factories
    
na pasta:
 
   src/main/resources/META-INF

em seguida, adicione a seguinte configuração, contendo o caminho completo 
da classe Base64ProtocolResolver:
    
    org.springframework.context.ApplicationContextInitializer=auth.util.Base64ProtocolResolverFactory
 */
// interface ApplicationContextInitializer, que é a interface responsável por inserir configurações adicionais na nossa aplicação, antes mesmo que ela inicie.
@Component
public class Base64ProtocolResolverFactory implements ProtocolResolver,
		ApplicationContextInitializer<ConfigurableApplicationContext> {

	@Override
	public void initialize(ConfigurableApplicationContext configurableApplicationContext) {
		configurableApplicationContext.addProtocolResolver(this);
	}

	@Override
	public Resource resolve(String location, ResourceLoader resourceLoader) {
		if (location.startsWith("base64:")) {
			byte[] decodedResource = Base64.getDecoder().decode(location.substring(7));
			return new ByteArrayResource(decodedResource);
		}

		return null;
	}

}