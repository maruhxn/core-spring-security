package study.corespringsecurity.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import study.corespringsecurity.domain.Account;

public interface UserRepository extends JpaRepository<Account, Long> {
}
