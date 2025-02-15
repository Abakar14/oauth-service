package com.bytmasoft.dss.repository;


import com.bytmasoft.common.repository.UtilRepository;
import com.bytmasoft.dss.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;


public interface UserRepository extends JpaRepository<User, Long>, JpaSpecificationExecutor<User>, UtilRepository {

    Optional<User> findByUsername(String username);

    @Query(value = "SELECT u FROM User u WHERE u.username=:usernameOrEmail Or u.email=:usernameOrEmail", nativeQuery = true)
    User findByUsernameOrEmail(@Param("usernameOrEmail") String usernameOrEmail);
}
