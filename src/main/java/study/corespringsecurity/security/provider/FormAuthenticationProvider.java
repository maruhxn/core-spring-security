package study.corespringsecurity.security.provider;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import study.corespringsecurity.security.common.FormWebAuthenticationDetails;
import study.corespringsecurity.security.service.AccountContext;

@Component
public class FormAuthenticationProvider implements AuthenticationProvider {

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

        FormWebAuthenticationDetails authenticationDetails = (FormWebAuthenticationDetails) authentication.getDetails();
        String secretKey = authenticationDetails.getSecretKey();

        if (!"secret".equals(secretKey)) {
            throw new InsufficientAuthenticationException("올바르지 않은 요청 데이터입니다.");
        }

        return UsernamePasswordAuthenticationToken.authenticated(
                accountContext.getAccount(),
                null,
                accountContext.getAuthorities());
    }

    @Override // 지원 여부 확인을 위한 구현
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
