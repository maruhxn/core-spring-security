//package study.corespringsecurity.security.config;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.core.annotation.Order;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.ProviderManager;
//import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.authentication.AuthenticationFailureHandler;
//import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
//import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//import org.springframework.security.web.context.DelegatingSecurityContextRepository;
//import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
//import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
//import org.springframework.security.web.context.SecurityContextRepository;
//import study.corespringsecurity.security.common.AjaxLoginAuthenticationEntryPoint;
//import study.corespringsecurity.security.filter.AjaxLoginProcessingFilter;
//import study.corespringsecurity.security.handler.AjaxAccessDeniedHandler;
//import study.corespringsecurity.security.handler.AjaxAuthenticationFailureHandler;
//import study.corespringsecurity.security.handler.AjaxAuthenticationSuccessHandler;
//import study.corespringsecurity.security.provider.AjaxAuthenticationProvider;
//
//@Configuration
//@EnableWebSecurity
//public class AjaxSecurityConfig {
//    @Autowired
//    private AuthenticationConfiguration authenticationConfiguration;
//
//    @Bean
//    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
//        ProviderManager authenticationManager = (ProviderManager) authenticationConfiguration.getAuthenticationManager();
//        // ajaxAuthenticationProvider 도 초기화때 생성된 AuthenticationManager 에서 추가해 주어야 한다.
//        authenticationManager.getProviders().add(ajaxAuthenticationProvider());
//        return authenticationManager;
//    }
//
//    @Bean
//    public AjaxAuthenticationProvider ajaxAuthenticationProvider() {
//        return new AjaxAuthenticationProvider();
//    }
//
//    @Bean
//    public AuthenticationSuccessHandler ajaxAuthenticationSuccessHandler() {
//        return new AjaxAuthenticationSuccessHandler();
//    }
//
//    @Bean
//    public AuthenticationFailureHandler ajaxAuthenticationFailureHandler() {
//        return new AjaxAuthenticationFailureHandler();
//    }
//
//    @Bean
//    @Order(0)
//    public SecurityFilterChain apiFilterChain(HttpSecurity http) throws Exception {
//        http
//                .securityMatcher("/api/**")
//                .formLogin(AbstractHttpConfigurer::disable)
//                .securityContext((securityContext) -> {
//                    securityContext.securityContextRepository(securityContextRepository());
//                })
//                .authorizeHttpRequests(authz ->
//                        authz
//                                .requestMatchers("/api/messages").hasRole("MANAGER")
//                                .requestMatchers("/api/login").permitAll()
//                                .anyRequest().authenticated())
////                .addFilterBefore(ajaxLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
//                .exceptionHandling(exceptionHandling ->
//                        exceptionHandling
//                                .authenticationEntryPoint(new AjaxLoginAuthenticationEntryPoint())
//                                .accessDeniedHandler(new AjaxAccessDeniedHandler()));
//
//        customConfigurerAjax(http);
//        return http.build();
//    }
//
//    private void customConfigurerAjax(HttpSecurity http) throws Exception {
//        http
//                .with(new AjaxLoginConfigurer<>(), dsl ->
//                {
//                    try {
//                        dsl
//                                .successHandlerAjax(ajaxAuthenticationSuccessHandler())
//                                .failureHandlerAjax(ajaxAuthenticationFailureHandler())
//                                .setAuthenticationManager(authenticationManager(authenticationConfiguration))
//                                .loginProcessingUrl("/api/login");
//                    } catch (Exception e) {
//                        throw new RuntimeException(e);
//                    }
//                })
//        ;
//    }
//
//
////    @Bean
////    public AjaxLoginProcessingFilter ajaxLoginProcessingFilter() throws Exception {
////        AjaxLoginProcessingFilter ajaxLoginProcessingFilter = new AjaxLoginProcessingFilter();
////        ajaxLoginProcessingFilter.setAuthenticationManager(authenticationManager(authenticationConfiguration));
////        ajaxLoginProcessingFilter.setAuthenticationSuccessHandler(ajaxAuthenticationSuccessHandler());
////        ajaxLoginProcessingFilter.setAuthenticationFailureHandler(ajaxAuthenticationFailureHandler());
////        return ajaxLoginProcessingFilter;
////    }
//
//    @Bean
//    public SecurityContextRepository securityContextRepository() {
//        return new DelegatingSecurityContextRepository(
//                new RequestAttributeSecurityContextRepository(),
//                new HttpSessionSecurityContextRepository()
//        );
//    }
//}
