package auth.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import auth.model.UserRole;

@Repository
public interface UserRoleRepository extends JpaRepository<UserRole, Long> {
	

	Optional<UserRole> findByEmail(String email);
	
    @Query(value = """
    		select concat('ROLE_' , r.name) from user u, user_has_role ur, role r
			where u.id = ur.user_id and ur.role_id = r.id 
			and u.email = :email
			union
			select a.name from user u, user_has_role ur, role r, role_has_authority ra, authority a
			where u.id = ur.user_id and ur.role_id = r.id and r.id = ra.role_id and ra.authority_id = a.id
			and u.email = :email    		
    		""",
    nativeQuery = true)
    List<String> listAuthoritiesByEmail(@Param("email") String email);
}
