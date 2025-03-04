
#===================================================
#Endpoint de Requisição de autorização do fluxo Authorization Code
http://auth-server:8081/oauth2/authorize?response_type=code&client_id=webclient1&state=abc&redirect_uri=http://127.0.0.1:8080/authorize&scope=read

#Endpoint de Tokens: ex: GrantType
http://auth-server:8081/oauth2/token
POST

#Endpoint de Introspecção:
http://auth-server:8081/oauth2/introspect
POST

#Endpoint de Chave Publica do servidor (JWKS)
http://auth-server:8081/oauth2/jwks

#Endpoints do protocolo OAUTH2 configurados no servidor:
org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings.builder()

.authorizationEndpoint("/oauth2/authorize")
.deviceAuthorizationEndpoint("/oauth2/device_authorization")
.deviceVerificationEndpoint("/oauth2/device_verification")
.tokenEndpoint("/oauth2/token")
.jwkSetEndpoint("/oauth2/jwks")
.tokenRevocationEndpoint("/oauth2/revoke")
.tokenIntrospectionEndpoint("/oauth2/introspect")
.oidcClientRegistrationEndpoint("/connect/register")
.oidcUserInfoEndpoint("/userinfo")
.oidcLogoutEndpoint("/connect/logout");
#===================================================

https://www.baeldung.com/spring-security-oauth-auth-server

#GitHub do Projeto:
https://github.com/spring-projects/spring-authorization-server

#sql:
https://github.com/spring-projects/spring-authorization-server/tree/main/oauth2-authorization-server/src/main/resources/org/springframework/security/oauth2/server/authorization



