package study.corespringsecurity.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import study.corespringsecurity.domain.dto.AccountDto;
import study.corespringsecurity.security.token.AjaxAuthenticationToken;
import study.corespringsecurity.security.utils.WebUtil;

import java.io.IOException;

@Component
public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

    private static final String XML_HTTP_REQUEST = "XMLHttpRequest";
    private static final String X_REQUESTED_WITH = "X-Requested-With";
    private final ObjectMapper objectMapper = new ObjectMapper();
    @Autowired
    private SecurityContextRepository securityContextRepository;

    public AjaxLoginProcessingFilter() {
        super(new AntPathRequestMatcher("/api/login", "POST")); // 이 URL일 때만 요청 처리
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        if (!HttpMethod.POST.name().equals(request.getMethod()) || !WebUtil.isAjax(request)) {
            throw new IllegalArgumentException("Authentication method not supported");
        }


        AccountDto accountDto = objectMapper.readValue(request.getReader(), AccountDto.class);

        if (!StringUtils.hasText(accountDto.getUsername()) || !StringUtils.hasText(accountDto.getPassword())) {
            throw new IllegalArgumentException("Username or Password is empty.");
        }

        AjaxAuthenticationToken ajaxAuthenticationToken =
                AjaxAuthenticationToken.unauthenticated(accountDto.getUsername(), accountDto.getPassword());

        Authentication authenticate = getAuthenticationManager().authenticate(ajaxAuthenticationToken);

        if (authenticate != null) {
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authenticate);
            SecurityContextHolder.setContext(context);
            RequestContextHolder.currentRequestAttributes().setAttribute("SPRING_SECURITY_CONTEXT", context, RequestAttributes.SCOPE_SESSION);
        }
        return authenticate;
    }
}
