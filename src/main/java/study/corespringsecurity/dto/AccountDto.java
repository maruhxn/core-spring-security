package study.corespringsecurity.dto;

import lombok.Data;
import study.corespringsecurity.domain.Account;

@Data
public class AccountDto {

    private String username;
    private String password;
    private String email;
    private String age;
    private String role;

    public static Account toEntity(AccountDto accountDto) {
        return Account.builder()
                .username(accountDto.getUsername())
                .password(accountDto.getPassword())
                .email(accountDto.getEmail())
                .age(accountDto.getAge())
                .role(accountDto.getRole())
                .build();
    }
}
