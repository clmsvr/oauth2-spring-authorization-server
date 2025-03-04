-- https://docs.spring.io/spring-boot/how-to/data-initialization.html

set foreign_key_checks = 0;

drop table IF EXISTS user_has_role;
drop table IF EXISTS role_has_authority;
drop table IF EXISTS user;
drop table IF EXISTS role;
drop table IF EXISTS authority;

drop table IF EXISTS oauth2_authorization_consent;
drop table IF EXISTS oauth2_authorization;
drop table IF EXISTS oauth2_registered_client;

truncate table spring_session;
truncate table spring_session_attributes;

set foreign_key_checks = 1;

-- -----------------------------------------------------
-- Table User
-- -----------------------------------------------------
CREATE TABLE user (
  id BIGINT NOT NULL AUTO_INCREMENT,
  email VARCHAR(100) NOT NULL,
  name VARCHAR(100) NOT NULL,
  password VARCHAR(200) NOT NULL,
  
  creation_date DATETIME not null,
  update_date DATETIME not null,
  PRIMARY KEY (id),
  UNIQUE INDEX email_UNIQUE (email ASC) )
ENGINE = InnoDB default character set = utf8mb4;

-- -----------------------------------------------------
-- Table role
-- -----------------------------------------------------
CREATE TABLE role (
  id BIGINT NOT NULL AUTO_INCREMENT,
  name VARCHAR(20) NOT NULL,
  description varchar(255),
  PRIMARY KEY (id))
ENGINE = InnoDB default character set = utf8mb4;

-- -----------------------------------------------------
-- Table User_has_role
-- -----------------------------------------------------
CREATE TABLE user_has_role (
  user_id BIGINT NOT NULL,
  role_id BIGINT NOT NULL,
  PRIMARY KEY (user_id, role_id),
  INDEX fk_user_has_role_role1_idx (role_id ASC) ,
  INDEX fk_user_has_role_user1_idx (user_id ASC) ,
  CONSTRAINT fk_user_has_role_user1
    FOREIGN KEY (user_id)
    REFERENCES user (id)
  ,
  CONSTRAINT fk_user_has_role_role1
    FOREIGN KEY (role_id)
    REFERENCES role (id)
  )
ENGINE = InnoDB default character set = utf8mb4;


-- -----------------------------------------------------
-- Table Authority
-- -----------------------------------------------------
CREATE TABLE authority (
  id BIGINT NOT NULL AUTO_INCREMENT,
  name VARCHAR(20) NOT NULL,
  description varchar(255),
  PRIMARY KEY (id))
ENGINE = InnoDB default character set = utf8mb4;


-- -----------------------------------------------------
-- Table role_has_Authority
-- -----------------------------------------------------
CREATE TABLE role_has_authority (
  role_id BIGINT NOT NULL,
  authority_id BIGINT NOT NULL,
  PRIMARY KEY (role_id, authority_id),
  INDEX fk_role_has_authority_authority_idx (authority_id ASC) ,
  INDEX fk_role_has_authority_role_idx (role_id ASC) ,
  CONSTRAINT fk_role_has_authority_role1
    FOREIGN KEY (role_id)
    REFERENCES role (id)
  ,
  CONSTRAINT fk_role_has_authority_authority1
    FOREIGN KEY (authority_id)
    REFERENCES authority (id)
  )
ENGINE = InnoDB default character set = utf8mb4;





-- https://github.com/spring-projects/spring-authorization-server/blob/main/oauth2-authorization-server/src/main/resources/org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql
CREATE TABLE oauth2_authorization_consent (
    registered_client_id varchar(100) NOT NULL,
    principal_name varchar(200) NOT NULL,
    authorities varchar(1000) NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name)
);

-- https://github.com/spring-projects/spring-authorization-server/blob/main/oauth2-authorization-server/src/main/resources/org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql
-- IMPORTANT:
--    If using PostgreSQL, update ALL columns defined with 'blob' to 'text',
--    as PostgreSQL does not support the 'blob' data type.
CREATE TABLE oauth2_authorization (
    id varchar(100) NOT NULL,
    registered_client_id varchar(100) NOT NULL,
    principal_name varchar(200) NOT NULL,
    authorization_grant_type varchar(100) NOT NULL,
    authorized_scopes varchar(1000) DEFAULT NULL,
    attributes blob DEFAULT NULL,
    state varchar(500) DEFAULT NULL,
    authorization_code_value blob DEFAULT NULL,
    authorization_code_issued_at timestamp DEFAULT NULL,
    authorization_code_expires_at timestamp DEFAULT NULL,
    authorization_code_metadata blob DEFAULT NULL,
    access_token_value blob DEFAULT NULL,
    access_token_issued_at timestamp DEFAULT NULL,
    access_token_expires_at timestamp DEFAULT NULL,
    access_token_metadata blob DEFAULT NULL,
    access_token_type varchar(100) DEFAULT NULL,
    access_token_scopes varchar(1000) DEFAULT NULL,
    oidc_id_token_value blob DEFAULT NULL,
    oidc_id_token_issued_at timestamp DEFAULT NULL,
    oidc_id_token_expires_at timestamp DEFAULT NULL,
    oidc_id_token_metadata blob DEFAULT NULL,
    refresh_token_value blob DEFAULT NULL,
    refresh_token_issued_at timestamp DEFAULT NULL,
    refresh_token_expires_at timestamp DEFAULT NULL,
    refresh_token_metadata blob DEFAULT NULL,
    user_code_value blob DEFAULT NULL,
    user_code_issued_at timestamp DEFAULT NULL,
    user_code_expires_at timestamp DEFAULT NULL,
    user_code_metadata blob DEFAULT NULL,
    device_code_value blob DEFAULT NULL,
    device_code_issued_at timestamp DEFAULT NULL,
    device_code_expires_at timestamp DEFAULT NULL,
    device_code_metadata blob DEFAULT NULL,
    PRIMARY KEY (id)
);

# https://github.com/spring-projects/spring-authorization-server/blob/main/oauth2-authorization-server/src/main/resources/org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql
CREATE TABLE oauth2_registered_client (
    id varchar(100) NOT NULL,
    client_id varchar(100) NOT NULL,
    client_id_issued_at timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
    client_secret varchar(200) DEFAULT NULL,
    client_secret_expires_at timestamp DEFAULT NULL,
    client_name varchar(200) NOT NULL,
    client_authentication_methods varchar(1000) NOT NULL,
    authorization_grant_types varchar(1000) NOT NULL,
    redirect_uris varchar(1000) DEFAULT NULL,
    post_logout_redirect_uris varchar(1000) DEFAULT NULL,
    scopes varchar(1000) NOT NULL,
    client_settings varchar(2000) NOT NULL,
    token_settings varchar(2000) NOT NULL,
    PRIMARY KEY (id)
);



