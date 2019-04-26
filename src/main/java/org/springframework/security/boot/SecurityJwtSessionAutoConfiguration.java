package org.springframework.security.boot;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.biz.authentication.AuthenticatingFailureCounter;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.property.SecurityLogoutProperties;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.biz.property.SessionFixationPolicy;
import org.springframework.security.boot.jwt.authentication.JwtAuthcOrAuthzFailureHandler;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationEntryPoint;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.RememberMeServices;
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

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityJwtSessionProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityJwtSessionProperties.class })
public class SecurityJwtSessionAutoConfiguration extends WebSecurityConfigurerAdapter{

	@Autowired
	private SecurityJwtSessionProperties jwtProperties;
	
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
				jwtProperties.getInvalidSessionUrl());
		invalidSessionStrategy.setCreateNewSession(jwtProperties.getSessionMgt().isAllowSessionCreation());
		return invalidSessionStrategy;
	}

	@Bean("jwtExpiredSessionStrategy")
	public SessionInformationExpiredStrategy jwtExpiredSessionStrategy() {
		return new SimpleRedirectSessionInformationExpiredStrategy(jwtProperties.getInvalidSessionUrl(), jwtRedirectStrategy());
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
	
	@Bean
	public JwtAuthcOrAuthzFailureHandler jwtAuthcOrAuthzFailureHandler() {
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
	@Autowired(required = false) 
	private List<AuthenticationListener> authenticationListeners;
	
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
    @Autowired
    private JwtAuthcOrAuthzFailureHandler jwtAuthcOrAuthzFailureHandler;
    
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
    		.sessionAuthenticationErrorUrl(sessionMgt.getFailureUrl())
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
        	.requestCache(jwtRequestCache);
        
        http.exceptionHandling().authenticationEntryPoint(jwtAuthenticationEntryPoint());
        
    }

}
