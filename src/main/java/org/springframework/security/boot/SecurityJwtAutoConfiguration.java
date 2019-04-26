package org.springframework.security.boot;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.boot.biz.authentication.AuthenticatingFailureCounter;
import org.springframework.security.boot.biz.authentication.AuthenticatingFailureRequestCounter;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.biz.property.SessionFixationPolicy;
import org.springframework.security.boot.biz.userdetails.BaseAuthenticationUserDetailsService;
import org.springframework.security.boot.jwt.authentication.JwtAuthcOrAuthzFailureHandler;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationEntryPoint;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationProvider;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationSuccessHandler;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationProvider;
import org.springframework.security.boot.jwt.userdetails.JwtPayloadRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.security.web.session.SimpleRedirectInvalidSessionStrategy;
import org.springframework.security.web.session.SimpleRedirectSessionInformationExpiredStrategy;

@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityJwtProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityJwtProperties.class })
public class SecurityJwtAutoConfiguration{

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
		// requestCache.setPortResolver(portResolver);
		// requestCache.setRequestMatcher(requestMatcher);
		// requestCache.setSessionAttrName(sessionAttrName);
		return requestCache;
	}

	@Bean("jwtInvalidSessionStrategy")
	public InvalidSessionStrategy jwtInvalidSessionStrategy() {
		SimpleRedirectInvalidSessionStrategy invalidSessionStrategy = new SimpleRedirectInvalidSessionStrategy(
				jwtProperties.getAuthc().getRedirectUrl());
		invalidSessionStrategy.setCreateNewSession(jwtProperties.getSessionMgt().isAllowSessionCreation());
		return invalidSessionStrategy;
	}

	@Bean("jwtExpiredSessionStrategy")
	public SessionInformationExpiredStrategy jwtExpiredSessionStrategy(RedirectStrategy redirectStrategy) {
		return new SimpleRedirectSessionInformationExpiredStrategy(jwtProperties.getAuthc().getRedirectUrl(), redirectStrategy);
	}
	
	@Bean("jwtCsrfTokenRepository")
	public CsrfTokenRepository jwtCsrfTokenRepository() {
		// Session 管理器配置参数
		SecuritySessionMgtProperties sessionMgt = jwtProperties.getSessionMgt();
		if (SessionFixationPolicy.CHANGE_SESSION_ID.equals(sessionMgt.getFixationPolicy())) {
			return new CookieCsrfTokenRepository();
		}
		return new HttpSessionCsrfTokenRepository();
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
	
	@Bean("jwtAuthenticatingFailureCounter")
	public AuthenticatingFailureCounter jwtAuthenticatingFailureCounter() {
		AuthenticatingFailureRequestCounter  failureCounter = new AuthenticatingFailureRequestCounter();
		failureCounter.setRetryTimesKeyParameter(jwtProperties.getAuthc().getRetryTimesKeyParameter());
		return failureCounter;
	}
	
	/*
	 *################################################################### 
	 *# Jwt认证 (authentication) 配置
	 *###################################################################
	 */

	@Bean
	public JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint() {

		JwtAuthenticationEntryPoint entryPoint = new JwtAuthenticationEntryPoint();
		
		return entryPoint;
	}
	
	@Bean
	public JwtAuthenticationProvider jwtAuthenticationProvider(BaseAuthenticationUserDetailsService userDetailsService,
			PasswordEncoder passwordEncoder) {
		return new JwtAuthenticationProvider(userDetailsService, passwordEncoder);
	}
	
	@Bean
	public JwtAuthenticationSuccessHandler jwtAuthenticationSuccessHandler(JwtPayloadRepository payloadRepository, 
			@Autowired(required = false) List<AuthenticationListener> authenticationListeners) {
		return new JwtAuthenticationSuccessHandler(payloadRepository, authenticationListeners);
	}
	
	
	/*
	 *################################################################### 
	 *# Jwt授权 (authorization)配置
	 *###################################################################
	 */
	
	@Bean
	public JwtAuthcOrAuthzFailureHandler jwtAuthorizationFailureHandler(
			@Autowired(required = false) List<AuthenticationListener> authenticationListeners,
			RedirectStrategy redirectStrategy) {
		JwtAuthcOrAuthzFailureHandler failureHandler = new JwtAuthcOrAuthzFailureHandler(
				authenticationListeners);
		failureHandler.setAllowSessionCreation(jwtProperties.getSessionMgt().isAllowSessionCreation());
		failureHandler.setRedirectStrategy(redirectStrategy);
		failureHandler.setUseForward(jwtProperties.getAuthc().isUseForward());
		return failureHandler;
	}

	@Bean
	public JwtAuthorizationProvider jwtAuthorizationProvider(BaseAuthenticationUserDetailsService userDetailsService) {
		return new JwtAuthorizationProvider(userDetailsService);
	}

}
