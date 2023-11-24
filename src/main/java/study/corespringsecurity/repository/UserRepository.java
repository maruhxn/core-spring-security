package study.corespringsecurity.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import study.corespringsecurity.domain.Account;

import java.util.Optional;

public interface UserRepository extends JpaRepository<Account, Long> {
    Optional<Account> findByUsername(String username);
}
