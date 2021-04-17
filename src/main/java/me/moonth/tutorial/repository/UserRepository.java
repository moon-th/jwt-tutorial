package me.moonth.tutorial.repository;

import me.moonth.tutorial.entity.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import javax.persistence.Entity;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    @EntityGraph(attributePaths = "authorities")// LAZY 조회가 아닌 Eager 조회로 가져온다.
    Optional<User> findOneWithAuthoritiesByUsername(String username);

}
