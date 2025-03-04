package auth.security;

import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.encrypt.KeyStoreKeyFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import auth.service.AuthQueryService;
import auth.service.AuthQueryServiceImpl;
import auth.util.JwtKeyStoreProperties;
import auth.util.SecurityProperties;

//O ApplicationServer, pode ser configurado via arquivo application.properties. 
//Vide: https://docs.spring.io/spring-authorization-server/reference/getting-started.html#developing-your-first-application

@Configuration
@EnableWebSecurity 
public class AuthServerConfig {
	
	//Configura apenas  os endpois de Autorização.
 	//A Spring Security filter chain para os Endpoints de AUTORIZACAO (protocolo OAUTH2)
	@Bean
	@Order(1)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
	throws Exception 
	{
		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
				OAuth2AuthorizationServerConfigurer.authorizationServer();

		//27.18 - Customizar a pagina de Consentimento do OAuth2
		authorizationServerConfigurer.authorizationEndpoint(cust -> 
			cust.consentPage("/oauth2/consent")
		);
		
		http
		    //!!! The http.securityMatcher() states that this HttpSecurity is applicable only 
		    //    to URLs that start with os endpoints deste ResquestMatcher.
		    // https://docs.spring.io/spring-security/reference/servlet/configuration/java.html#_multiple_httpsecurity_instances
			// Este parametro RequestMatcher tem todos os endpois de Autorização.
			// Vide: org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings.builder()
            // https://docs.spring.io/spring-authorization-server/reference/configuration-model.html
			.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
			.with(authorizationServerConfigurer, (authorizationServer) ->
				authorizationServer.oidc(Customizer.withDefaults())	// Enable OpenID Connect 1.0
			)
			.authorizeHttpRequests((t) ->
				t.anyRequest().authenticated()
			)
			//.csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
			.csrf(t -> t.disable()) //meu			
			// Redirect to the login page when not authenticated from the authorization endpoint
			.exceptionHandling((exceptions) -> exceptions
				.defaultAuthenticationEntryPointFor(
					new LoginUrlAuthenticationEntryPoint("/login"),
					new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
				)
			)
			//meu
			.cors(Customizer.withDefaults()) 
			;
			
//			//Estava na documentacao antiga. EX: https://docs.spring.io/spring-authorization-server/reference/1.2/getting-started.html
//			//Accept access tokens for User Info and/or Client Registration
//          //nao precisa 		
//		    .oauth2ResourceServer((t) -> 
//				t.jwt(Customizer.withDefaults()));			
//			;

		return http.build();
	}
	
	//Configura os DEMAIS Endpoints, incluindo os de Login
	//A Spring Security filter chain for authentication.
	@Bean
	@Order(2)
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
			throws Exception {
		
		//observe que nao chama: .securityMatcher()
		http
			.authorizeHttpRequests(cust -> cust
				.anyRequest().authenticated()
			)
			.csrf(cust -> cust.disable())
			.cors(Customizer.withDefaults())
			 // Form login handles the redirect to the login page from the
			 // authorization server filter chain
			.formLogin(cust -> cust.loginPage("/login").permitAll())
			 //este logout nao funciona para a Conceções de escopo
			.logout(cust -> cust.logoutRequestMatcher(new AntPathRequestMatcher("/logout")).logoutSuccessUrl("/").permitAll());

		return http.build();
	}
	
	//@Bean
	public AuthorizationServerSettings providerSettings(SecurityProperties props) {
	    return AuthorizationServerSettings.builder() //configura os endpoints do AuthServer.
	      .issuer(props.getProviderUrl()) //"http://auth-server:8081" importante para identificar quem assina os tokens.
	      .build();
	}
	
	//Clients Apps
	///@Bean
	public RegisteredClientRepository registeredClientRepository1(
			PasswordEncoder passwordEncoder, JdbcOperations jdbcOperations) 
	{
		RegisteredClient postman1 = RegisteredClient.withId("postman1")
				.clientId("postman1")
				.clientSecret(passwordEncoder.encode("123"))
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)// o refresh token será sempre um token OPACO pq ele nao pose ser usado fora do applicationServer.
				//escopos que o cliente pode usar
				.scope("write")
				.scope("read")
				.scope(OidcScopes.OPENID) // 'openid' scope is auto-approved as it does not require consent
				.scope("profile")
				.scope("email")
				.tokenSettings(
						TokenSettings.builder()
						.accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)//JWT Tokens
						.accessTokenTimeToLive(Duration.ofMinutes(60*3))
						.reuseRefreshTokens(false)
						.refreshTokenTimeToLive(Duration.ofMinutes(60*12))
						.build())
				.redirectUri("https://oidcdebugger.com/debug") //nao pode usar 'localhost'
				.redirectUri("http://127.0.0.1:8181/authorize")
				.redirectUri("https://oauth.pstmn.io/v1/callback")//posman
				.redirectUri("http://localhost:8080/swagger-ui/oauth2-redirect.html")//swagger-ui	
				.redirectUri("http://127.0.0.1:5500/index.html")
				.postLogoutRedirectUri("http://127.0.0.1:8080/") // ??????
				.clientSettings(ClientSettings.builder()
						.requireAuthorizationConsent(true)//!!! cliente precisa autorizar um escopo
						//.requireProofKey(false)  //testar: obrigar o uso de PKCE ou state ??
						.build())
				.build();
		
				RegisteredClient device1 = RegisteredClient.withId("device1")
						.clientId("device1")
						.clientSecret(passwordEncoder.encode("123"))
						.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
						.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
						.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
						.scope("write")
						.scope("read")
						.scope(OidcScopes.OPENID)
						.tokenSettings(
								TokenSettings.builder()
								.accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED) //JWT
								.accessTokenTimeToLive(Duration.ofMinutes(30))
								.reuseRefreshTokens(false)
								.refreshTokenTimeToLive(Duration.ofMinutes(60*12))
								.build())
						.clientSettings(ClientSettings.builder()
								.requireAuthorizationConsent(true)//!!! nao consede permissões automaticamente. O usuario TEM que consentir no processo de login e autorizar um dos escopos
								.build())
						.build();

//27.16 salva a configuração de clientes no banco de dados. 	
//após salvar:
//		eliminamos o codigo deta função, 
//		inserimos os inserts no "afterMigrate.sql"
//		usamos a função abaixo: registeredClientRepository()
		
//		JdbcRegisteredClientRepository rep = 
//				new JdbcRegisteredClientRepository(jdbcOperations);
//		rep.save(postman1);
//		rep.save(device1);
//		//return rep;

	
		return new InMemoryRegisteredClientRepository(Arrays.asList(postman1,device1));
	}

	
//Este metodo implementa o uso do banco de dados para os Clientes.
//Descomentar e eliminar o metodo acima In Memory.
//    @Bean
    public RegisteredClientRepository registeredClientRepository(
    		PasswordEncoder passwordEncoder,
    		JdbcOperations jdbcOperations) 
    {
        return new JdbcRegisteredClientRepository(jdbcOperations);
    }
    
    
    //UTIL quando os clients estao gravados no banco pois eh muito dificil alterar lá.
    //Fonte: https://www.appsdeveloperblog.com/spring-authorization-server-tutorial/
    /*
    requireAuthorizationConsent: This property determines whether the authorization server requires user consent for each authorization request or not. If set to false, the user consent screen is skipped, and the authorization server grants the requested scopes automatically.
    requireProofKey: This property determines whether the authorization server requires proof of possession of a key for each authorization request or not. If set to false, the authorization server does not enforce PKCE (Proof Key for Code Exchange) validation.
    The method returns a ClientSettings object with these properties set to false, which means that the authorization server does not require user consent or proof of key for any client.    
     */
    //@Bean
    public ClientSettings clientSettings() {
        return ClientSettings.builder()
                .requireAuthorizationConsent(false)
                .requireProofKey(false)
                .build();
    }    

	
	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	//Salva os TOKENs e codigos de autorizacao no Banco de Dados. 
	//só descomentar o Bean
    @Bean
    public OAuth2AuthorizationService authorizationService(
    		JdbcOperations jdbcOperations,
    		RegisteredClientRepository registeredClientRepository) 
    {
        return new JdbcOAuth2AuthorizationService(
                jdbcOperations,
                registeredClientRepository
        );
    }	
	
    @Bean
    public OAuth2AuthorizationConsentService consentService(
    		JdbcOperations jdbcOperations,
    		RegisteredClientRepository clientRepository) 
    {
    	//return new InMemoryOAuth2AuthorizationConsentService();
    	
    	//Util quando usado em nuvem com varias instancias.
        return new JdbcOAuth2AuthorizationConsentService(jdbcOperations, clientRepository);
    }
    
    
    //Informa as Chaves RSA Publica e Privada para o AuthorizationServer gerar e assinar Tokens JWK.
    @Bean
    public JWKSource<SecurityContext> jwkSource(JwtKeyStoreProperties properties) 
    throws Exception 
    {
    	//23.9
    	//obter o keystore (do classpath)
//		var jksResource = new ClassPathResource("keystores/authserver.jks");
//		char[] keyStorePass = "authserver".toCharArray();
//		var keypairAlias = "authserver";
		
    	//obter o keystore (do aplication.properties - armazenado no formato BASE64)
    	//ver Base64ProtocolResolver.class criada paraconverter os dados em "Resource"
        char[] keyStorePass = properties.getPassword().toCharArray();
        String keypairAlias = properties.getKeypairAlias();
        Resource jksResource = properties.getJksLocation();
        
        //ler o keystore
        InputStream inputStream = jksResource.getInputStream();
        KeyStore keyStore = KeyStore.getInstance("JKS");//java key store
        keyStore.load(inputStream, keyStorePass);

        //projeto Nimbus
        RSAKey rsaKey = RSAKey.load(keyStore, keypairAlias, keyStorePass);
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));      
    }

    //outro exemplo. Nao Usado.
    //23.45
    //@Bean
	public JWKSet jwkSet(JwtKeyStoreProperties properties) {
        char[] keyStorePass = properties.getPassword().toCharArray();
        String keypairAlias = properties.getKeypairAlias();
		
		var keyStoreKeyFactory = new KeyStoreKeyFactory(
				properties.getJksLocation(), keyStorePass);
		
		KeyPair keypair = keyStoreKeyFactory.getKeyPair(keypairAlias);
		
		RSAKey.Builder builder = new RSAKey.Builder((RSAPublicKey) keypair.getPublic())
				.keyUse(KeyUse.SIGNATURE)
				.algorithm(JWSAlgorithm.RS256)
				.keyID("auth-key-id");
		
		return new JWKSet(builder.build());
	}
	
//Solução de exemplo do Spring.
//Gera uma chave diferente toda vez que o servidor levanta,
	//Each authorization server needs its signing key for tokens to keep a proper 
	//boundary between security domains. Let's generate a 2048-byte RSA key:
	//@Bean
	public JWKSource<SecurityContext> jwkSource() 
	{
		// Cria par de chaves publicas e privadas, Toda vez que a aplicaçõ inicializa. 
		// Não serve como solução.
		KeyPair keyPair = generateRsaKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		
		//Converter para um JWKSource do projeto Nimbus ()
		
		RSAKey rsaKey = new RSAKey.Builder(publicKey)
				.privateKey(privateKey)
				.keyID(UUID.randomUUID().toString())
				.build();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return new ImmutableJWKSet<>(jwkSet); // implementação de JWKSource
	}
    
	private static KeyPair generateRsaKey() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}

	
	// 23.5 - Geracao de JWT com chave simetrica - NAO DEVE SER USADO - NAO TESTADO
	// Solução pesquisada por mim para uso de Chave SIMETRICA. 
	// https://connect2id.com/products/nimbus-jose-jwt/examples/validating-jwt-access-tokens#key-sources
	// Quem tem a chave pode verificar tokens e também GERAR novos tokens sem precisar do AuthServer. !!!
	// Nao temos exemplo desta implementação no novo AuthorizationServer. Usamos apenas chaves assimetricas.
	//@Bean
	public JWKSource<SecurityContext> jwkSimetricSource() 
	{
		String secret = "89a7sd89f7as98f7dsa98fds7fd89sasd9898asdf98s";
		// Create JWK source backed by a singleton secret key
	    SecretKey key = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
	    JWKSource<SecurityContext> keySource = new ImmutableSecret<SecurityContext>(key);
	    //return new NimbusJwtEncoder(immutableSecret);	
	    return keySource;
	}	
	
	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}
	
	//27.14
	//Customizar o token Antes de ele ser Criado. Nao tem como alterar o Token jwt depois que foi gerado.
	//Customizar o token jwt com outros dados do usuario e suas Grants.
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer()
    {
        return jwtEncodingContext -> {
            Authentication authentication = jwtEncodingContext.getPrincipal();
           
            //verificar - nem todos os fluxos tem informação do usuario. Ex: client credentials
            if (authentication.getPrincipal() instanceof User user) {

                //Nao vamos acessar o banco pois coloquei os dados adicionais como Authorities do tipo "CLAIM_...". Veja em "JpaUserDetailsService"
				
                Set<String> authorities = new HashSet<>();
                
                for (GrantedAuthority authority : user.getAuthorities()) 
                {
                	String aut = authority.getAuthority();
                	if (aut.startsWith("CLAIM_")) { //Vide "JpaUserDetailsService"
                		String[] split = aut.split("_");
                		jwtEncodingContext.getClaims().claim(split[1], split[2]);
                	}
                	else 
                		authorities.add(authority.getAuthority());
                }               
                //Os valores precisam ser strings
                jwtEncodingContext.getClaims().claim("authorities", authorities);
            }
        };
    }	
    
    
    @Bean
    public AuthQueryService auth2AuthorizationQueryService(
    		JdbcOperations jdbcOperations,
    		RegisteredClientRepository repository) 
    {
        return new AuthQueryServiceImpl(jdbcOperations, repository);
    }    
     
    
//    //https://reflectoring.io/spring-boot-conditionals/
//    @Bean
//    //@Profile("DEV")
//    @ConditionalOnProperty(
//    	    value="spring.session.store-type", 
//    	    havingValue = "none", 
//    	    matchIfMissing = true)    
//    public SessionRepository<?> sessionRepository()
//    {
//    	return new MapSessionRepository(new HashMap<String, Session>());
//    }
}

