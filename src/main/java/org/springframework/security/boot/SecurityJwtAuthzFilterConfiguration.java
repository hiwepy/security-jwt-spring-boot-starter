package org.springframework.security.boot;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.biz.authentication.AuthenticatingFailureCounter;
import org.springframework.security.boot.biz.property.SecurityLogoutProperties;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.jwt.authentication.JwtAuthcOrAuthzFailureHandler;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationEntryPoint;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationProcessingFilter;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationProvider;
import org.springframework.security.boot.jwt.property.SecurityJwtAuthcProperties;
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
@EnableConfigurationProperties({ SecurityJwtProperties.class, SecurityJwtAuthcProperties.class, SecurityJwtAuthzProperties.class })
@Order(106)
public class SecurityJwtAuthzFilterConfiguration extends WebSecurityConfigurerAdapter  implements ApplicationEventPublisherAware {

	private ApplicationEventPublisher eventPublisher;
	
	@Autowired
	private SecurityJwtProperties jwtProperties;
	@Autowired
	private SecurityJwtAuthcProperties jwtAuthcProperties;
	@Autowired
	private SecurityJwtAuthzProperties jwtAuthzProperties;
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
     
    @Autowired
    private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    @Autowired
    private JwtAuthcOrAuthzFailureHandler jwtAuthcOrAuthzFailureHandler;
    @Autowired
    private JwtAuthorizationProvider jwtAuthorizationProvider;
    
    @Bean
    public JwtAuthorizationProcessingFilter jwtAuthorizationProcessingFilter() {
    	
    	JwtAuthorizationProcessingFilter authcFilter = new JwtAuthorizationProcessingFilter();
		
		authcFilter.setAllowSessionCreation(jwtAuthzProperties.isAllowSessionCreation());
		authcFilter.setApplicationEventPublisher(eventPublisher);
		authcFilter.setAuthenticationFailureHandler(jwtAuthcOrAuthzFailureHandler);
		authcFilter.setAuthenticationManager(authenticationManager);
		authcFilter.setAuthenticationSuccessHandler(new AuthenticationSuccessHandler() {
			public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
					Authentication authentication) throws IOException, ServletException {
				// no-op - just allow filter chain to continue to token endpoint
			}
		});
		authcFilter.setContinueChainBeforeSuccessfulAuthentication(jwtAuthzProperties.isContinueChainBeforeSuccessfulAuthentication());
		if (StringUtils.hasText(jwtAuthzProperties.getPathPattern())) {
			authcFilter.setFilterProcessesUrl(jwtAuthzProperties.getPathPattern());
		}
		if (StringUtils.hasText(jwtAuthcProperties.getLoginUrlPattern())) {
			authcFilter.setLoginFilterProcessesUrl(jwtAuthcProperties.getLoginUrlPattern());
		}
		authcFilter.setAuthorizationCookieName(jwtAuthzProperties.getAuthorizationCookieName());
		authcFilter.setAuthorizationHeaderName(jwtAuthzProperties.getAuthorizationHeaderName());
		authcFilter.setAuthorizationParamName(jwtAuthzProperties.getAuthorizationParamName());
		authcFilter.setRememberMeServices(rememberMeServices);
		authcFilter.setSessionAuthenticationStrategy(jwtSessionAuthenticationStrategy);
		
        return authcFilter;
    }
 
	 
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(jwtAuthorizationProvider)
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
    		.sessionAuthenticationErrorUrl(jwtAuthcProperties.getFailureUrl())
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
