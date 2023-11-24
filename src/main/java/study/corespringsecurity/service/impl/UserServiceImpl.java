package study.corespringsecurity.service.impl;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import study.corespringsecurity.domain.Account;
import study.corespringsecurity.dto.AccountDto;
import study.corespringsecurity.repository.UserRepository;
import study.corespringsecurity.service.UserService;

@Service
@RequiredArgsConstructor
@Transactional
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void createUser(AccountDto accountDto) {
        accountDto.setPassword(passwordEncoder.encode(accountDto.getPassword()));
        Account account = AccountDto.toEntity(accountDto);
        userRepository.save(account);
    }
}
