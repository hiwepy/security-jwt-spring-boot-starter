package org.springframework.security.boot;

import java.util.List;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.property.SecurityLogoutProperties;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.biz.property.SessionFixationPolicy;
import org.springframework.security.boot.jwt.authentication.JwtAuthcOrAuthzFailureHandler;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationEntryPoint;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.security.web.session.SimpleRedirectInvalidSessionStrategy;
import org.springframework.security.web.session.SimpleRedirectSessionInformationExpiredStrategy;

@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@EnableConfigurationProperties({ SecurityJwtProperties.class })
public class SecurityJwtAutoConfiguration {

	@Autowired
	private SecurityJwtProperties jwtProperties;
	
	@Bean("jwtRedirectStrategy")
	public RedirectStrategy jwtRedirectStrategy() {
		DefaultRedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
		redirectStrategy.setContextRelative(jwtProperties.getRedirect().isContextRelative());
		return redirectStrategy;
	}

	@Bean("jwtRequestCache")
	public RequestCache jwtRequestCache() {
		HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
		requestCache.setCreateSessionAllowed(jwtProperties.getSessionMgt().isAllowSessionCreation());
		requestCache.setSessionAttrName(jwtProperties.getSessionMgt().getSessionAttrName());
		return requestCache;
	}

	@Bean("jwtInvalidSessionStrategy")
	public InvalidSessionStrategy jwtInvalidSessionStrategy() {
		SimpleRedirectInvalidSessionStrategy invalidSessionStrategy = new SimpleRedirectInvalidSessionStrategy(
				jwtProperties.getInvalidSessionUrl());
		invalidSessionStrategy.setCreateNewSession(jwtProperties.getSessionMgt().isAllowSessionCreation());
		return invalidSessionStrategy;
	}

	@Bean("jwtExpiredSessionStrategy")
	public SessionInformationExpiredStrategy jwtExpiredSessionStrategy() {
		return new SimpleRedirectSessionInformationExpiredStrategy(jwtProperties.getInvalidSessionUrl(), jwtRedirectStrategy());
	}

	@Bean("jwtSessionAuthenticationStrategy")
	public SessionAuthenticationStrategy jwtSessionAuthenticationStrategy() {
		// Session 管理器配置参数
		SecuritySessionMgtProperties sessionMgt = jwtProperties.getSessionMgt();
		if (SessionFixationPolicy.CHANGE_SESSION_ID.equals(sessionMgt.getFixationPolicy())) {
			return new ChangeSessionIdAuthenticationStrategy();
		} else if (SessionFixationPolicy.MIGRATE_SESSION.equals(sessionMgt.getFixationPolicy())) {
			return new SessionFixationProtectionStrategy();
		} else if (SessionFixationPolicy.NEW_SESSION.equals(sessionMgt.getFixationPolicy())) {
			SessionFixationProtectionStrategy sessionFixationProtectionStrategy = new SessionFixationProtectionStrategy();
			sessionFixationProtectionStrategy.setMigrateSessionAttributes(false);
			return sessionFixationProtectionStrategy;
		} else {
			return new NullAuthenticatedSessionStrategy();
		}
	}

	@Bean("jwtSecurityContextLogoutHandler")
	public SecurityContextLogoutHandler jwtSecurityContextLogoutHandler() {

		SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
		logoutHandler.setClearAuthentication(jwtProperties.getLogout().isClearAuthentication());
		logoutHandler.setInvalidateHttpSession(jwtProperties.getLogout().isInvalidateHttpSession());

		return logoutHandler;
	}

	@Bean
	public JwtAuthcOrAuthzFailureHandler jwtAuthcOrAuthzFailureHandler(@Autowired(required = false) List<AuthenticationListener> authenticationListeners) {
		JwtAuthcOrAuthzFailureHandler failureHandler = new JwtAuthcOrAuthzFailureHandler(
				authenticationListeners);
		failureHandler.setAllowSessionCreation(jwtProperties.getSessionMgt().isAllowSessionCreation());
		failureHandler.setRedirectStrategy(jwtRedirectStrategy());
		failureHandler.setUseForward(jwtProperties.isUseForward());
		return failureHandler;
	}
	
	@Bean
	public JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint() {

		JwtAuthenticationEntryPoint entryPoint = new JwtAuthenticationEntryPoint();
		
		return entryPoint;
	}
    
    @Configuration
	@EnableConfigurationProperties({ SecurityJwtProperties.class, SecurityBizProperties.class })
    @Order(105)
	static class JwtWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

    	private final SecurityJwtProperties jwtProperties;
    	private final JwtAuthenticationEntryPoint authenticationEntryPoint;
    	private final JwtAuthcOrAuthzFailureHandler authenticationFailureHandler;

    	private final InvalidSessionStrategy invalidSessionStrategy;
		private final RequestCache requestCache;
		private final SecurityContextLogoutHandler securityContextLogoutHandler;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
		private final SessionRegistry sessionRegistry;
		private final SessionInformationExpiredStrategy expiredSessionStrategy;
		
		public JwtWebSecurityConfigurerAdapter(
				SecurityJwtProperties jwtProperties,
				ObjectProvider<JwtAuthenticationEntryPoint> authenticationEntryPointProvider,
				ObjectProvider<JwtAuthcOrAuthzFailureHandler> authenticationFailureHandlerProvider, 
				@Qualifier("jwtInvalidSessionStrategy") ObjectProvider<InvalidSessionStrategy> invalidSessionStrategyProvider,
				@Qualifier("jwtRequestCache") ObjectProvider<RequestCache> requestCacheProvider,
				@Qualifier("jwtSecurityContextLogoutHandler")  ObjectProvider<SecurityContextLogoutHandler> securityContextLogoutHandlerProvider,
				@Qualifier("jwtSessionAuthenticationStrategy") ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider,
				ObjectProvider<SessionRegistry> sessionRegistryProvider,
				@Qualifier("jwtExpiredSessionStrategy") ObjectProvider<SessionInformationExpiredStrategy> expiredSessionStrategyProvider) {
			this.jwtProperties = jwtProperties;
			this.authenticationEntryPoint = authenticationEntryPointProvider.getIfAvailable();
			this.authenticationFailureHandler = authenticationFailureHandlerProvider.getIfAvailable();

			this.invalidSessionStrategy = invalidSessionStrategyProvider.getIfAvailable();
			this.requestCache = requestCacheProvider.getIfAvailable();
			this.securityContextLogoutHandler = securityContextLogoutHandlerProvider.getIfAvailable();
			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
			this.sessionRegistry = sessionRegistryProvider.getIfAvailable();
			this.expiredSessionStrategy = expiredSessionStrategyProvider.getIfAvailable();
		}

	    @Override
	    protected void configure(AuthenticationManagerBuilder auth) {
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
	        
	        http.exceptionHandling().authenticationEntryPoint(authenticationEntryPoint);
			
		}

	}

}
