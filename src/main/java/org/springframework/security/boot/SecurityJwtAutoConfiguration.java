package org.springframework.security.boot;

import java.util.List;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.property.SecurityLogoutProperties;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.jwt.authentication.JwtMatchedAuthcOrAuthzFailureHandler;
import org.springframework.security.boot.jwt.authentication.JwtMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.jwt.authentication.JwtMatchedAuthenticationSuccessHandler;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.security.web.session.SimpleRedirectInvalidSessionStrategy;
import org.springframework.security.web.session.SimpleRedirectSessionInformationExpiredStrategy;

@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@EnableConfigurationProperties({ SecurityBizProperties.class, SecurityJwtProperties.class })
public class SecurityJwtAutoConfiguration {
	
	@Autowired
	private SecurityBizProperties bizProperties;
	@Autowired
	private SecurityJwtProperties jwtProperties;

	@Bean("jwtExpiredSessionStrategy")
	public SessionInformationExpiredStrategy jwtExpiredSessionStrategy() {
		return new SimpleRedirectSessionInformationExpiredStrategy(jwtProperties.getInvalidSessionUrl(), jwtRedirectStrategy());
	}
	
	@Bean("jwtRedirectStrategy")
	public RedirectStrategy jwtRedirectStrategy() {
		DefaultRedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
		redirectStrategy.setContextRelative(jwtProperties.getRedirect().isContextRelative());
		return redirectStrategy;
	}

	@Bean("jwtSecurityContextLogoutHandler")
	public SecurityContextLogoutHandler jwtSecurityContextLogoutHandler() {

		SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
		logoutHandler.setClearAuthentication(jwtProperties.getLogout().isClearAuthentication());
		logoutHandler.setInvalidateHttpSession(jwtProperties.getLogout().isInvalidateHttpSession());

		return logoutHandler;
	}
	
	@Bean("jwtInvalidSessionStrategy")
	public InvalidSessionStrategy jwtInvalidSessionStrategy() {
		SimpleRedirectInvalidSessionStrategy invalidSessionStrategy = new SimpleRedirectInvalidSessionStrategy(
				jwtProperties.getInvalidSessionUrl());
		invalidSessionStrategy.setCreateNewSession(bizProperties.getSessionMgt().isAllowSessionCreation());
		return invalidSessionStrategy;
	}

	@Bean("jwtAuthenticationSuccessHandler")
	public PostRequestAuthenticationSuccessHandler jwtAuthenticationSuccessHandler(
			@Autowired(required = false) List<AuthenticationListener> authenticationListeners,
			@Autowired(required = false) List<MatchedAuthenticationSuccessHandler> successHandlers) {
		
		PostRequestAuthenticationSuccessHandler successHandler = new PostRequestAuthenticationSuccessHandler(
				authenticationListeners, successHandlers);
		
		successHandler.setDefaultTargetUrl(jwtProperties.getAuthc().getSuccessUrl());
		successHandler.setStateless(bizProperties.isStateless());
		successHandler.setTargetUrlParameter(jwtProperties.getAuthc().getTargetUrlParameter());
		successHandler.setUseReferer(jwtProperties.getAuthc().isUseReferer());
		
		return successHandler;
	}
	
	@Bean("jwtAuthenticationFailureHandler")
	public PostRequestAuthenticationFailureHandler jwtAuthenticationFailureHandler(
			@Autowired(required = false) List<AuthenticationListener> authenticationListeners,
			@Autowired(required = false) List<MatchedAuthenticationFailureHandler> failureHandlers, 
			@Qualifier("jwtRedirectStrategy") RedirectStrategy redirectStrategy) {
		
		PostRequestAuthenticationFailureHandler failureHandler = new PostRequestAuthenticationFailureHandler(
				authenticationListeners, failureHandlers);
		
		failureHandler.setAllowSessionCreation(jwtProperties.getAuthc().isAllowSessionCreation());
		failureHandler.setDefaultFailureUrl(jwtProperties.getAuthc().getFailureUrl());
		failureHandler.setRedirectStrategy(redirectStrategy);
		failureHandler.setStateless(bizProperties.isStateless());
		failureHandler.setUseForward(jwtProperties.getAuthc().isUseForward());
		
		return failureHandler;
		
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
    
    @Configuration
	@EnableConfigurationProperties({ SecurityJwtProperties.class, SecurityBizProperties.class })
    @Order(105)
	static class JwtWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
    	
    	private final SecurityBizProperties bizProperties;
    	private final SecurityJwtProperties jwtProperties;
    	private final PostRequestAuthenticationFailureHandler authenticationFailureHandler;
    	private final InvalidSessionStrategy invalidSessionStrategy;
		private final RequestCache requestCache;
		private final SecurityContextLogoutHandler securityContextLogoutHandler;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
		private final SessionRegistry sessionRegistry;
		private final SessionInformationExpiredStrategy expiredSessionStrategy;
		
		public JwtWebSecurityConfigurerAdapter(
				SecurityBizProperties bizProperties,
				SecurityJwtProperties jwtProperties,
				@Qualifier("jwtAuthenticationFailureHandler") ObjectProvider<PostRequestAuthenticationFailureHandler> authenticationFailureHandlerProvider,
				@Qualifier("jwtInvalidSessionStrategy") ObjectProvider<InvalidSessionStrategy> invalidSessionStrategyProvider,
				ObjectProvider<RequestCache> requestCacheProvider,
				@Qualifier("jwtSecurityContextLogoutHandler")  ObjectProvider<SecurityContextLogoutHandler> securityContextLogoutHandlerProvider,
				@Qualifier("jwtSessionAuthenticationStrategy") ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider,
				ObjectProvider<SessionRegistry> sessionRegistryProvider,
				@Qualifier("jwtExpiredSessionStrategy") ObjectProvider<SessionInformationExpiredStrategy> expiredSessionStrategyProvider) {
			
			this.bizProperties = bizProperties;
			this.jwtProperties = jwtProperties;
			this.authenticationFailureHandler = authenticationFailureHandlerProvider.getIfAvailable();

			this.invalidSessionStrategy = invalidSessionStrategyProvider.getIfAvailable();
			this.requestCache = requestCacheProvider.getIfAvailable();
			this.securityContextLogoutHandler = securityContextLogoutHandlerProvider.getIfAvailable();
			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
			this.sessionRegistry = sessionRegistryProvider.getIfAvailable();
			this.expiredSessionStrategy = expiredSessionStrategyProvider.getIfAvailable();
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			
			http.csrf().disable(); // We don't need CSRF for JWT based authentication
	    	
	    	// Session 管理器配置参数
	    	SecuritySessionMgtProperties sessionMgt = bizProperties.getSessionMgt();
	    	// Session 注销配置参数
	    	SecurityLogoutProperties logout = jwtProperties.getLogout();
	    	
		    // Session 管理器配置
	    	http.sessionManagement()
	    		.enableSessionUrlRewriting(sessionMgt.isEnableSessionUrlRewriting())
	    		.invalidSessionStrategy(invalidSessionStrategy)
	    		.invalidSessionUrl(jwtProperties.getLogout().getLogoutUrl())
	    		.maximumSessions(sessionMgt.getMaximumSessions())
	    		.maxSessionsPreventsLogin(sessionMgt.isMaxSessionsPreventsLogin())
	    		.expiredSessionStrategy(expiredSessionStrategy)
				.expiredUrl(jwtProperties.getLogout().getLogoutUrl())
				.sessionRegistry(sessionRegistry)
				.and()
	    		.sessionAuthenticationErrorUrl(sessionMgt.getFailureUrl())
	    		.sessionAuthenticationFailureHandler(authenticationFailureHandler)
	    		.sessionAuthenticationStrategy(sessionAuthenticationStrategy)
	    		.sessionCreationPolicy(sessionMgt.getCreationPolicy())
	    		// Session 注销配置
	    		.and()
	    		.logout()
	    		.addLogoutHandler(securityContextLogoutHandler)
	    		.clearAuthentication(logout.isClearAuthentication())
	        	// Request 缓存配置
	        	.and()
	    		.requestCache()
	        	.requestCache(requestCache);
			
		}

	}

}
