package org.springframework.security.boot;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.boot.biz.authentication.AuthenticatingFailureCounter;
import org.springframework.security.boot.biz.authentication.AuthenticatingFailureRequestCounter;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.authentication.captcha.CaptchaResolver;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.property.SecurityLogoutProperties;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationProcessingFilter;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationProvider;
import org.springframework.security.boot.jwt.authentication.JwtMatchedAuthcOrAuthzFailureHandler;
import org.springframework.security.boot.jwt.authentication.JwtMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.jwt.authentication.JwtMatchedAuthenticationSuccessHandler;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.CompositeLogoutHandler;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.web.cors.CorsConfigurationSource;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.vindell.jwt.JwtPayload;

@Configuration
@AutoConfigureBefore({ SecurityFilterAutoConfiguration.class })
@ConditionalOnProperty(prefix = SecurityJwtAuthcProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityBizProperties.class, SecurityJwtAuthcProperties.class })
public class SecurityJwtAuthcFilterConfiguration {

	@Bean("jwtAuthenticationSuccessHandler")
	public PostRequestAuthenticationSuccessHandler jwtAuthenticationSuccessHandler(
			SecurityBizProperties bizProperties,
			SecurityJwtAuthcProperties jwtAuthcProperties,
			@Autowired(required = false) List<AuthenticationListener> authenticationListeners,
			@Autowired(required = false) List<MatchedAuthenticationSuccessHandler> successHandlers) {
		
		PostRequestAuthenticationSuccessHandler successHandler = new PostRequestAuthenticationSuccessHandler(
				authenticationListeners, successHandlers);
		
		successHandler.setDefaultTargetUrl(jwtAuthcProperties.getSuccessUrl());
		successHandler.setStateless(bizProperties.isStateless());
		successHandler.setTargetUrlParameter(jwtAuthcProperties.getTargetUrlParameter());
		successHandler.setUseReferer(jwtAuthcProperties.isUseReferer());
		
		return successHandler;
	}
	
	@Bean
	@ConditionalOnMissingBean
	public JwtMatchedAuthcOrAuthzFailureHandler jwtMatchedAuthcOrAuthzFailureHandler() {
		return new JwtMatchedAuthcOrAuthzFailureHandler();
	}
	
	@Bean
	@ConditionalOnMissingBean
	public JwtMatchedAuthenticationEntryPoint jwtMatchedAuthenticationEntryPoint() {
		return new JwtMatchedAuthenticationEntryPoint();
	}

	@Bean
	@ConditionalOnMissingBean
	public JwtMatchedAuthenticationSuccessHandler jwtMatchedAuthenticationSuccessHandler(JwtPayloadRepository payloadRepository) {
		return new JwtMatchedAuthenticationSuccessHandler(payloadRepository);
	}

	@Bean
	@ConditionalOnMissingBean
	public JwtPayloadRepository payloadRepository() {
		return new JwtPayloadRepository() {

			@Override
			public String issueJwt(AbstractAuthenticationToken token) {
				return null;
			}

			@Override
			public boolean verify(AbstractAuthenticationToken token, boolean checkExpiry) throws AuthenticationException {
				return false;
			}

			@Override
			public JwtPayload getPayload(AbstractAuthenticationToken token, boolean checkExpiry) {
				return null;
			}
			
		};
	}
	
	@Bean
	public JwtAuthenticationProvider jwtAuthenticationProvider(UserDetailsServiceAdapter userDetailsService, PasswordEncoder passwordEncoder) {
		return new JwtAuthenticationProvider(userDetailsService, passwordEncoder);
	}
    
	@Bean("jwtAuthenticatingFailureCounter")
	public AuthenticatingFailureCounter jwtAuthenticatingFailureCounter(SecurityJwtAuthcProperties jwtAuthcProperties) {
		AuthenticatingFailureRequestCounter  failureCounter = new AuthenticatingFailureRequestCounter();
		failureCounter.setRetryTimesKeyParameter(jwtAuthcProperties.getRetryTimesKeyParameter());
		return failureCounter;
	}
	
	@Bean("jwtLogoutSuccessHandler")
	public LogoutSuccessHandler jwtLogoutSuccessHandler() {
		return new HttpStatusReturningLogoutSuccessHandler();
	}
	
	@Configuration
	@ConditionalOnProperty(prefix = SecurityJwtAuthcProperties.PREFIX, value = "enabled", havingValue = "true")
	@EnableConfigurationProperties({ SecurityBizProperties.class, SecurityJwtAuthcProperties.class })
    @Order(SecurityProperties.DEFAULT_FILTER_ORDER + 9)
	static class JwtAuthcWebSecurityConfigurerAdapter extends SecurityBizConfigurerAdapter {
    	
		private final SecurityBizProperties bizProperties;
		private final SecurityJwtAuthcProperties authcProperties;
		
		private final AuthenticationManager authenticationManager;
	    private final AuthenticatingFailureCounter authenticatingFailureCounter;
	    private final JwtAuthenticationProvider authenticationProvider;
	    private final PostRequestAuthenticationSuccessHandler authenticationSuccessHandler;
	    private final PostRequestAuthenticationFailureHandler authenticationFailureHandler;
	    private final CaptchaResolver captchaResolver;
	    private final InvalidSessionStrategy invalidSessionStrategy;
	    private final LogoutSuccessHandler logoutSuccessHandler;
	    private final List<LogoutHandler> logoutHandlers;
	    private final ObjectMapper objectMapper;
    	private final RequestCache requestCache;
    	private final RememberMeServices rememberMeServices;
    	private final SessionRegistry sessionRegistry;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
		private final SessionInformationExpiredStrategy sessionInformationExpiredStrategy;
		
		public JwtAuthcWebSecurityConfigurerAdapter(
				
				SecurityBizProperties bizProperties,
   				SecurityJwtAuthcProperties jwtAuthcProperties,
   				
   				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
   				ObjectProvider<JwtAuthenticationProvider> authenticationProvider,
   				ObjectProvider<AuthenticatingFailureCounter> authenticatingFailureCounter,
   				ObjectProvider<PostRequestAuthenticationFailureHandler> authenticationFailureHandler,
   				@Qualifier("jwtAuthenticationSuccessHandler") ObjectProvider<PostRequestAuthenticationSuccessHandler> authenticationSuccessHandler,
   				ObjectProvider<CaptchaResolver> captchaResolverProvider,
   				ObjectProvider<CsrfTokenRepository> csrfTokenRepositoryProvider,
   				ObjectProvider<CorsConfigurationSource> configurationSourceProvider,
   				ObjectProvider<InvalidSessionStrategy> invalidSessionStrategyProvider,
   				@Qualifier("jwtLogoutSuccessHandler") ObjectProvider<LogoutSuccessHandler> logoutSuccessHandlerProvider,
   				ObjectProvider<LogoutHandler> logoutHandlerProvider,
   				ObjectProvider<ObjectMapper> objectMapperProvider,
				ObjectProvider<RequestCache> requestCacheProvider,
				ObjectProvider<RememberMeServices> rememberMeServicesProvider,
				ObjectProvider<SessionRegistry> sessionRegistryProvider,
				ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider,
				ObjectProvider<SessionInformationExpiredStrategy> sessionInformationExpiredStrategyProvider
				
   			) {
		    
			super(bizProperties, csrfTokenRepositoryProvider.getIfAvailable(), configurationSourceProvider.getIfAvailable());
   			
   			this.bizProperties = bizProperties;
   			this.authcProperties = jwtAuthcProperties;
   			
   			this.authenticationManager = authenticationManagerProvider.getIfAvailable();
   			this.authenticationProvider = authenticationProvider.getIfAvailable();
   			this.authenticatingFailureCounter = authenticatingFailureCounter.getIfAvailable();
   			this.authenticationFailureHandler = authenticationFailureHandler.getIfAvailable();
   			this.authenticationSuccessHandler = authenticationSuccessHandler.getIfAvailable();
   			this.captchaResolver = captchaResolverProvider.getIfAvailable();
   			this.invalidSessionStrategy = invalidSessionStrategyProvider.getIfAvailable();
   			this.logoutSuccessHandler = logoutSuccessHandlerProvider.getIfAvailable();
   			this.logoutHandlers = logoutHandlerProvider.stream().collect(Collectors.toList());
   			this.objectMapper = objectMapperProvider.getIfAvailable();
   			this.requestCache = requestCacheProvider.getIfAvailable();
   			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
   			this.sessionRegistry = sessionRegistryProvider.getIfAvailable();
   			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
   			this.sessionInformationExpiredStrategy = sessionInformationExpiredStrategyProvider.getIfAvailable();
   			
		}

		@Override
		public AuthenticationManager authenticationManagerBean() throws Exception {
   			AuthenticationManager parentManager = authenticationManager == null ? super.authenticationManagerBean() : authenticationManager;
			ProviderManager authenticationManager = new ProviderManager( Arrays.asList(authenticationProvider), parentManager);
			// 不擦除认证密码，擦除会导致TokenBasedRememberMeServices因为找不到Credentials再调用UserDetailsService而抛出UsernameNotFoundException
			authenticationManager.setEraseCredentialsAfterAuthentication(false);
			return authenticationManager;
		}

		public JwtAuthenticationProcessingFilter authenticationProcessingFilter() throws Exception {
	    	
	        JwtAuthenticationProcessingFilter authenticationFilter = new JwtAuthenticationProcessingFilter(objectMapper);
	        
	        /**
			 * 批量设置参数
			 */
			PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
			
			map.from(bizProperties.getSessionMgt().isAllowSessionCreation()).to(authenticationFilter::setAllowSessionCreation);
			
			map.from(authenticationManagerBean()).to(authenticationFilter::setAuthenticationManager);
			map.from(authenticationSuccessHandler).to(authenticationFilter::setAuthenticationSuccessHandler);
			map.from(authenticationFailureHandler).to(authenticationFilter::setAuthenticationFailureHandler);
			
			map.from(authcProperties.getPathPattern()).to(authenticationFilter::setFilterProcessesUrl);
			
			map.from(authcProperties.getCaptcha().getParamName()).to(authenticationFilter::setCaptchaParameter);
			// 是否验证码必填
			map.from(authcProperties.getCaptcha().isRequired()).to(authenticationFilter::setCaptchaRequired);
			// 验证码解析器
			map.from(captchaResolver).to(authenticationFilter::setCaptchaResolver);
			// 认证失败计数器
			map.from(authenticatingFailureCounter).to(authenticationFilter::setFailureCounter);
			
			map.from(authcProperties.getUsernameParameter()).to(authenticationFilter::setUsernameParameter);
			map.from(authcProperties.getPasswordParameter()).to(authenticationFilter::setPasswordParameter);
			map.from(authcProperties.isPostOnly()).to(authenticationFilter::setPostOnly);
			// 登陆失败重试次数，超出限制需要输入验证码
			map.from(authcProperties.getRetryTimesKeyAttribute()).to(authenticationFilter::setRetryTimesKeyAttribute);
			map.from(authcProperties.getRetryTimesWhenAccessDenied()).to(authenticationFilter::setRetryTimesWhenAccessDenied);
			
			map.from(rememberMeServices).to(authenticationFilter::setRememberMeServices);
			map.from(sessionAuthenticationStrategy).to(authenticationFilter::setSessionAuthenticationStrategy);
			map.from(authcProperties.isContinueChainBeforeSuccessfulAuthentication()).to(authenticationFilter::setContinueChainBeforeSuccessfulAuthentication);
			
	        return authenticationFilter;
	    }
		
		@Override
		public void configure(AuthenticationManagerBuilder auth) throws Exception {
	        auth.authenticationProvider(authenticationProvider);
	        super.configure(auth);
	    }

	    @Override
		public void configure(HttpSecurity http) throws Exception {
	    	
	    	// Session 管理器配置参数
   	    	SecuritySessionMgtProperties sessionMgt = bizProperties.getSessionMgt();
   	    	// Session 注销配置参数
   	    	SecurityLogoutProperties logout = authcProperties.getLogout();
   	    	
   	    	http.csrf().disable(); // We don't need CSRF for JWT based authentication
	    	http.headers().cacheControl(); // 禁用缓存
	    	
   		    // Session 管理器配置
   	    	http.sessionManagement()
   	    		.enableSessionUrlRewriting(sessionMgt.isEnableSessionUrlRewriting())
   	    		.invalidSessionStrategy(invalidSessionStrategy)
   	    		.invalidSessionUrl(logout.getLogoutUrl())
   	    		.maximumSessions(sessionMgt.getMaximumSessions())
   	    		.maxSessionsPreventsLogin(sessionMgt.isMaxSessionsPreventsLogin())
   	    		.expiredSessionStrategy(sessionInformationExpiredStrategy)
   				.expiredUrl(logout.getLogoutUrl())
   				.sessionRegistry(sessionRegistry)
   				.and()
   	    		.sessionAuthenticationErrorUrl(sessionMgt.getFailureUrl())
   	    		.sessionAuthenticationFailureHandler(authenticationFailureHandler)
   	    		.sessionAuthenticationStrategy(sessionAuthenticationStrategy)
   	    		.sessionCreationPolicy(sessionMgt.getCreationPolicy())
   	    		// Session 注销配置
   	    		.and()
   	    		.logout()
   	    		.logoutUrl(logout.getPathPatterns())
   	    		.logoutSuccessHandler(logoutSuccessHandler)
   	    		.addLogoutHandler(new CompositeLogoutHandler(logoutHandlers))
   	    		.clearAuthentication(logout.isClearAuthentication())
   	    		.invalidateHttpSession(logout.isInvalidateHttpSession())
   	        	// Request 缓存配置
   	        	.and()
   	    		.requestCache()
   	        	.requestCache(requestCache)
   	        	.and()
   	        	.antMatcher(authcProperties.getPathPattern())
   	        	.addFilterBefore(authenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class); 
   	    	
   	    	super.configure(http, authcProperties.getCros());
   	    	super.configure(http, authcProperties.getCsrf());
   	    	super.configure(http, authcProperties.getHeaders());
	    	super.configure(http);
	    }
	    
	    @Override
	    public void configure(WebSecurity web) throws Exception {
	    }
		
	}

}
