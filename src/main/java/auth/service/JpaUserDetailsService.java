package auth.service;

import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import auth.model.UserRole;
import auth.repository.UserRoleRepository;

@Service
public class JpaUserDetailsService implements UserDetailsService {
	
	@Autowired
	private UserRoleRepository usuarioRepository;
	
	//!!!!!!!!!
	//O repositorio fecha o EntityManager assim que retorna o usuario.
	//Esta anotação é para manter o EntityManager durante o contexto transacional
	//deste metodo, assim, podemos buscar as listas de grupo e permições
	//que são Fetch.LAZY por Default.
	@Transactional(readOnly = true) // readonly: indica que nao vamos fazer alteração.
	@Override
	public UserDetails loadUserByUsername(String username) 
	throws UsernameNotFoundException 
	{
		UserRole usuario = usuarioRepository.findByEmail(username)
				.orElseThrow(() -> new UsernameNotFoundException("Usuário não encontrado com e-mail informado"));
		
		
		
		//Solução minha para o problema de nao poder extender o "User" para termos mais informação.
		//Adicionar uma authority "CLAIM_<prop>_<value>" para cada propriedade que desejamos adiocionar como CLAIM nos Tokens.
		var authorities = getAuthorities(usuario);
		authorities.add(new SimpleGrantedAuthority("CLAIM_sub_"+usuario.getId()));
		authorities.add(new SimpleGrantedAuthority("CLAIM_name_"+usuario.getName()));
		authorities.add(new SimpleGrantedAuthority("CLAIM_email_"+usuario.getEmail()));
		
		return new User(usuario.getEmail(), usuario.getPassword(), authorities);
	}
	
	private Collection<GrantedAuthority> getAuthorities(UserRole usuario) 
	{
		return usuario.getRoles().stream()
				.flatMap(r -> r.getAuthorities().stream())
				.map(authority -> new SimpleGrantedAuthority(authority.getName().toUpperCase()))
				.collect(Collectors.toSet()); //Set: usuario pode estar em dois grupos com permissoes repetidas
	}

}