package org.springframework.security.boot;

import java.util.List;

import org.springframework.beans.factory.ObjectProvider;
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
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.captcha.CaptchaResolver;
import org.springframework.security.boot.biz.authentication.captcha.NullCaptchaResolver;
import org.springframework.security.boot.biz.userdetails.AuthcUserDetailsService;
import org.springframework.security.boot.jwt.authentication.JwtAuthcOrAuthzFailureHandler;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationProcessingFilter;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationProvider;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationSuccessHandler;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationToken;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationToken;
import org.springframework.security.boot.jwt.property.SecurityJwtAuthcProperties;
import org.springframework.security.boot.jwt.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.vindell.jwt.JwtPayload;

@Configuration
@AutoConfigureAfter(SecurityBizFilterAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityJwtProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityJwtProperties.class, SecurityJwtAuthcProperties.class })
public class SecurityJwtAuthcFilterConfiguration implements ApplicationEventPublisherAware {

	private ApplicationEventPublisher eventPublisher;
	
	@Autowired
	private SecurityJwtProperties jwtProperties;
	@Autowired
	private SecurityJwtAuthcProperties jwtAuthcProperties;
	@Autowired
	private AuthenticationManager authenticationManager;
	@Autowired
	private ObjectMapper objectMapper;
	@Autowired
	private RememberMeServices rememberMeServices;
	@Autowired
	private AuthcUserDetailsService authcUserDetailsService;
	@Autowired
	private PasswordEncoder passwordEncoder;
	@Autowired
	@Qualifier("jwtAuthenticatingFailureCounter")
	private AuthenticatingFailureCounter jwtAuthenticatingFailureCounter;
	@Autowired
	@Qualifier("jwtSessionAuthenticationStrategy")
	private SessionAuthenticationStrategy jwtSessionAuthenticationStrategy;
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
    @Autowired
    private CaptchaResolver captchaResolver;
    
    @Autowired
    private JwtAuthenticationSuccessHandler jwtAuthenticationSuccessHandler;
    @Autowired
    private JwtAuthcOrAuthzFailureHandler jwtAuthcOrAuthzFailureHandler;
    
    /*
	 *################################################################### 
	 *# Jwt认证 (authentication) 配置
	 *###################################################################
	 */

    @Bean
	@ConditionalOnMissingBean 
	public CaptchaResolver captchaResolver() {
		return new NullCaptchaResolver();
	}
    
	@Bean
	@ConditionalOnMissingBean
	public JwtPayloadRepository payloadRepository() {
		return new JwtPayloadRepository() {

			@Override
			public String issueJwt(JwtAuthenticationToken token) {
				return null;
			}

			@Override
			public boolean verify(JwtAuthorizationToken token, boolean checkExpiry) throws AuthenticationException {
				return false;
			}

			@Override
			public JwtPayload getPayload(JwtAuthorizationToken token, boolean checkExpiry) {
				return null;
			}
			
		};
	}
	
	@Bean
	public JwtAuthenticationSuccessHandler jwtAuthenticationSuccessHandler(JwtPayloadRepository payloadRepository, 
			@Autowired(required = false) List<AuthenticationListener> authenticationListeners) {
		return new JwtAuthenticationSuccessHandler(payloadRepository, authenticationListeners);
	}
	

	@Bean("jwtAuthenticatingFailureCounter")
	public AuthenticatingFailureCounter jwtAuthenticatingFailureCounter() {
		AuthenticatingFailureRequestCounter  failureCounter = new AuthenticatingFailureRequestCounter();
		failureCounter.setRetryTimesKeyParameter(jwtAuthcProperties.getRetryTimesKeyParameter());
		return failureCounter;
	}
	
	@Bean
	public JwtAuthenticationProvider jwtAuthenticationProvider() {
		return new JwtAuthenticationProvider(authcUserDetailsService, passwordEncoder);
	}
    
    @Bean
    @ConditionalOnProperty(prefix = SecurityJwtAuthcProperties.PREFIX, value = "enabled", havingValue = "true")
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
		authcFilter.setContinueChainBeforeSuccessfulAuthentication(jwtAuthcProperties.isContinueChainBeforeSuccessfulAuthentication());
		if (StringUtils.hasText(jwtAuthcProperties.getLoginUrlPattern())) {
			authcFilter.setFilterProcessesUrl(jwtAuthcProperties.getLoginUrlPattern());
		}
		//authcFilter.setMessageSource(messageSource);
		authcFilter.setUsernameParameter(jwtAuthcProperties.getUsernameParameter());
		authcFilter.setPasswordParameter(jwtAuthcProperties.getPasswordParameter());
		authcFilter.setPostOnly(jwtAuthcProperties.isPostOnly());
		authcFilter.setRememberMeServices(rememberMeServices);
		authcFilter.setRetryTimesKeyAttribute(jwtAuthcProperties.getRetryTimesKeyAttribute());
		authcFilter.setRetryTimesWhenAccessDenied(jwtAuthcProperties.getRetryTimesWhenAccessDenied());
		authcFilter.setSessionAuthenticationStrategy(jwtSessionAuthenticationStrategy);
		
        return authcFilter;
    }
    
    
    @Configuration
    @ConditionalOnProperty(prefix = SecurityJwtAuthcProperties.PREFIX, value = "enabled", havingValue = "true")
    @EnableConfigurationProperties({ SecurityJwtProperties.class, SecurityBizProperties.class })
    @Order(106)
	static class JwtAuthcWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
    	
		private final JwtAuthenticationProvider authenticationProvider;
		private final JwtAuthenticationProcessingFilter authenticationProcessingFilter;
		private final UserDetailsService userDetailsService;
		
		public JwtAuthcWebSecurityConfigurerAdapter(
				ObjectProvider<UserDetailsService> userDetailsServiceProvider,
				ObjectProvider<JwtAuthenticationProvider> authorizationProvider,
				ObjectProvider<JwtAuthenticationProcessingFilter> authenticationProcessingFilterProvider) {
			this.userDetailsService = userDetailsServiceProvider.getIfAvailable();
			this.authenticationProvider = authorizationProvider.getIfAvailable();
			this.authenticationProcessingFilter = authenticationProcessingFilterProvider.getIfAvailable();
		}

		@Override
	    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	        auth.authenticationProvider(authenticationProvider)
	        	.userDetailsService(userDetailsService);
	    }

	    @Override
	    protected void configure(HttpSecurity http) throws Exception {
	    	http.csrf().disable(); // We don't need CSRF for JWT based authentication
	    	http.addFilterBefore(authenticationProcessingFilter, UsernamePasswordAuthenticationFilter.class);
	    }

	}
  

	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
		this.eventPublisher = applicationEventPublisher;
	}

}
