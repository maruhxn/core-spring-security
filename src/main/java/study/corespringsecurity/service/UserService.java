package study.corespringsecurity.service;

import study.corespringsecurity.domain.Account;
import study.corespringsecurity.dto.AccountDto;

public interface UserService {

    void createUser(AccountDto accountDto);
}
