package org.springframework.security.boot;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.biz.authentication.AuthenticatingFailureCounter;
import org.springframework.security.boot.biz.authentication.AuthenticatingFailureRequestCounter;
import org.springframework.security.boot.biz.authentication.captcha.CaptchaResolver;
import org.springframework.security.boot.biz.property.SecurityLogoutProperties;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.jwt.authentication.JwtAuthcOrAuthzFailureHandler;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationEntryPoint;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationProcessingFilter;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationProvider;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationSuccessHandler;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationProcessingFilter;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationProvider;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
@AutoConfigureAfter(SecurityBizFilterAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityJwtProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityJwtProperties.class })
@Order(106)
public class SecurityJwtFilterConfiguration extends WebSecurityConfigurerAdapter  implements ApplicationEventPublisherAware {

	private ApplicationEventPublisher eventPublisher;
	
	@Autowired
	private SecurityJwtProperties jwtProperties;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	@Autowired
	private ObjectMapper objectMapper;
	@Autowired
	private RememberMeServices rememberMeServices;
	@Autowired
    private SessionRegistry sessionRegistry;
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Autowired
	@Qualifier("jwtAuthenticatingFailureCounter")
	private AuthenticatingFailureCounter jwtAuthenticatingFailureCounter;
	@Autowired
	@Qualifier("jwtSessionAuthenticationStrategy")
	private SessionAuthenticationStrategy jwtSessionAuthenticationStrategy;
    @Autowired
    @Qualifier("jwtCsrfTokenRepository")
	private CsrfTokenRepository jwtCsrfTokenRepository;
    @Autowired
    @Qualifier("jwtExpiredSessionStrategy")
    private SessionInformationExpiredStrategy jwtExpiredSessionStrategy;
    @Autowired
    @Qualifier("jwtRequestCache")
    private RequestCache jwtRequestCache;
    @Autowired
    @Qualifier("jwtInvalidSessionStrategy")
    private InvalidSessionStrategy jwtInvalidSessionStrategy;
    @Autowired
    @Qualifier("jwtSecurityContextLogoutHandler") 
    private SecurityContextLogoutHandler jwtSecurityContextLogoutHandler;
    @Autowired(required = false)
    private CaptchaResolver captchaResolver;
     
    @Autowired
    private JwtAuthenticationProvider jwtAuthenticationProvider;
    @Autowired
    private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    @Autowired
    private JwtAuthenticationSuccessHandler jwtAuthenticationSuccessHandler;
    @Autowired
    private JwtAuthcOrAuthzFailureHandler jwtAuthcOrAuthzFailureHandler;
    @Autowired
    private JwtAuthorizationProvider jwtAuthorizationProvider;
    
    @Bean
	@ConditionalOnMissingBean
	public AuthenticatingFailureCounter jwtAuthenticatingFailureCounter() {
		AuthenticatingFailureRequestCounter  failureCounter = new AuthenticatingFailureRequestCounter();
		failureCounter.setRetryTimesKeyParameter(jwtProperties.getAuthc().getRetryTimesKeyParameter());
		return failureCounter;
	}
    
    @Bean
	public JwtAuthenticationProcessingFilter jwtAuthenticationProcessingFilter() throws Exception {
    	
        JwtAuthenticationProcessingFilter authcFilter = new JwtAuthenticationProcessingFilter(objectMapper);
        
        authcFilter.setCaptchaParameter(jwtProperties.getCaptcha().getParamName());
		// 是否验证码必填
		authcFilter.setCaptchaRequired(jwtProperties.getCaptcha().isRequired());
		// 登陆失败重试次数，超出限制需要输入验证码
		authcFilter.setRetryTimesWhenAccessDenied(jwtProperties.getCaptcha().getRetryTimesWhenAccessDenied());
		// 验证码解析器
		authcFilter.setCaptchaResolver(captchaResolver);
		// 认证失败计数器
		authcFilter.setFailureCounter(jwtAuthenticatingFailureCounter);

		authcFilter.setAllowSessionCreation(jwtProperties.getSessionMgt().isAllowSessionCreation());
		authcFilter.setApplicationEventPublisher(eventPublisher);
		authcFilter.setAuthenticationFailureHandler(jwtAuthcOrAuthzFailureHandler);
		authcFilter.setAuthenticationManager(authenticationManager);
		authcFilter.setAuthenticationSuccessHandler(jwtAuthenticationSuccessHandler);
		authcFilter.setContinueChainBeforeSuccessfulAuthentication(jwtProperties.getAuthc().isContinueChainBeforeSuccessfulAuthentication());
		if (StringUtils.hasText(jwtProperties.getAuthc().getLoginUrlPattern())) {
			authcFilter.setFilterProcessesUrl(jwtProperties.getAuthc().getLoginUrlPattern());
		}
		//authcFilter.setMessageSource(messageSource);
		authcFilter.setUsernameParameter(jwtProperties.getAuthc().getUsernameParameter());
		authcFilter.setPasswordParameter(jwtProperties.getAuthc().getPasswordParameter());
		authcFilter.setPostOnly(jwtProperties.getAuthc().isPostOnly());
		authcFilter.setRememberMeServices(rememberMeServices);
		authcFilter.setRetryTimesKeyAttribute(jwtProperties.getAuthc().getRetryTimesKeyAttribute());
		authcFilter.setRetryTimesWhenAccessDenied(jwtProperties.getAuthc().getRetryTimesWhenAccessDenied());
		authcFilter.setSessionAuthenticationStrategy(jwtSessionAuthenticationStrategy);
		
        return authcFilter;
    }
    
    @Bean
    public JwtAuthorizationProcessingFilter jwtAuthorizationProcessingFilter() {
    	
    	JwtAuthorizationProcessingFilter authcFilter = new JwtAuthorizationProcessingFilter();
		
		authcFilter.setAllowSessionCreation(jwtProperties.getAuthz().isAllowSessionCreation());
		authcFilter.setApplicationEventPublisher(eventPublisher);
		authcFilter.setAuthenticationFailureHandler(jwtAuthcOrAuthzFailureHandler);
		authcFilter.setAuthenticationManager(authenticationManager);
		authcFilter.setAuthenticationSuccessHandler(new AuthenticationSuccessHandler() {
			public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
					Authentication authentication) throws IOException, ServletException {
				// no-op - just allow filter chain to continue to token endpoint
			}
		});
		authcFilter.setContinueChainBeforeSuccessfulAuthentication(jwtProperties.getAuthz().isContinueChainBeforeSuccessfulAuthentication());
		if (StringUtils.hasText(jwtProperties.getAuthz().getPathPattern())) {
			authcFilter.setFilterProcessesUrl(jwtProperties.getAuthz().getPathPattern());
		}
		if (StringUtils.hasText(jwtProperties.getAuthc().getLoginUrlPattern())) {
			authcFilter.setLoginFilterProcessesUrl(jwtProperties.getAuthc().getLoginUrlPattern());
		}
		authcFilter.setAuthorizationCookieName(jwtProperties.getAuthz().getAuthorizationCookieName());
		authcFilter.setAuthorizationHeaderName(jwtProperties.getAuthz().getAuthorizationHeaderName());
		authcFilter.setAuthorizationParamName(jwtProperties.getAuthz().getAuthorizationParamName());
		authcFilter.setRememberMeServices(rememberMeServices);
		authcFilter.setSessionAuthenticationStrategy(jwtSessionAuthenticationStrategy);
		
        return authcFilter;
    }
 
	 
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(jwtAuthenticationProvider)
        	.authenticationProvider(jwtAuthorizationProvider)
        	.userDetailsService(userDetailsService);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
    	
    	http.csrf().disable(); // We don't need CSRF for JWT based authentication
    	
    	// Session 管理器配置参数
    	SecuritySessionMgtProperties sessionMgt = jwtProperties.getSessionMgt();
    	// Session 注销配置参数
    	SecurityLogoutProperties logout = jwtProperties.getLogout();
    	
	    // Session 管理器配置
    	http.sessionManagement()
    		.enableSessionUrlRewriting(sessionMgt.isEnableSessionUrlRewriting())
    		.invalidSessionStrategy(jwtInvalidSessionStrategy)
    		.invalidSessionUrl(jwtProperties.getLogout().getLogoutUrl())
    		.maximumSessions(sessionMgt.getMaximumSessions())
    		.maxSessionsPreventsLogin(sessionMgt.isMaxSessionsPreventsLogin())
    		.expiredSessionStrategy(jwtExpiredSessionStrategy)
			.expiredUrl(jwtProperties.getLogout().getLogoutUrl())
			.sessionRegistry(sessionRegistry)
			.and()
    		.sessionAuthenticationErrorUrl(jwtProperties.getAuthc().getFailureUrl())
    		.sessionAuthenticationFailureHandler(jwtAuthcOrAuthzFailureHandler)
    		.sessionAuthenticationStrategy(jwtSessionAuthenticationStrategy)
    		.sessionCreationPolicy(sessionMgt.getCreationPolicy())
    		// Session 注销配置
    		.and()
    		.logout()
    		.addLogoutHandler(jwtSecurityContextLogoutHandler)
    		.clearAuthentication(logout.isClearAuthentication())
        	// Request 缓存配置
        	.and()
    		.requestCache()
        	.requestCache(jwtRequestCache)
        	.and()
        	.addFilterBefore(jwtAuthenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
			.addFilterBefore(jwtAuthorizationProcessingFilter(), UsernamePasswordAuthenticationFilter.class);
        
        http.exceptionHandling().authenticationEntryPoint(jwtAuthenticationEntryPoint);
        
    }

	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
		this.eventPublisher = applicationEventPublisher;
	}

}
