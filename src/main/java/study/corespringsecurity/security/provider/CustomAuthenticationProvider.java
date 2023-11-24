package study.corespringsecurity.security.provider;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import study.corespringsecurity.security.service.AccountContext;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override // 검증을 위한 구현
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String username = authentication.getName();
        String password = (String) authentication.getCredentials();

        // username(id) 검증
        AccountContext accountContext = (AccountContext) userDetailsService.loadUserByUsername(username);

        // password 검증
        if (!passwordEncoder.matches(password, accountContext.getPassword())) {
            throw new BadCredentialsException("비밀번호가 일치하지 않습니다.");
        }

        UsernamePasswordAuthenticationToken authenticationToken = UsernamePasswordAuthenticationToken.authenticated(
                accountContext.getAccount(),
                null,
                accountContext.getAuthorities());

        return authenticationToken;
    }

    @Override // 지원 여부 확인을 위한 구현
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
