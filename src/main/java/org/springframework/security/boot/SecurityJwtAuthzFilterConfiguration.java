package org.springframework.security.boot;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.biz.authentication.AuthenticatingFailureCounter;
import org.springframework.security.boot.biz.userdetails.AuthcUserDetailsService;
import org.springframework.security.boot.jwt.authentication.JwtAuthcOrAuthzFailureHandler;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationProcessingFilter;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationProvider;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionRegistry;
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
@AutoConfigureBefore({ SecurityFilterAutoConfiguration.class })
@ConditionalOnProperty(prefix = SecurityJwtAuthzProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityJwtProperties.class, SecurityJwtAuthcProperties.class, SecurityJwtAuthzProperties.class })
public class SecurityJwtAuthzFilterConfiguration {

	@Bean
	public JwtAuthorizationProvider jwtAuthorizationProvider(AuthcUserDetailsService userDetailsService) {
		return new JwtAuthorizationProvider(userDetailsService);
	}
    
    @Configuration
    @ConditionalOnProperty(prefix = SecurityJwtAuthzProperties.PREFIX, value = "enabled", havingValue = "true")
	@EnableConfigurationProperties({ SecurityJwtProperties.class, SecurityJwtAuthcProperties.class, SecurityJwtAuthzProperties.class })
    @Order(107)
	static class JwtAuthzWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter implements ApplicationEventPublisherAware {

    	private ApplicationEventPublisher eventPublisher;
    	
    	private final AuthenticationManager authenticationManager;
	    private final RememberMeServices rememberMeServices;
	    
		private final SecurityJwtAuthcProperties jwtAuthcProperties;
    	private final SecurityJwtAuthzProperties jwtAuthzProperties;
 	    private final JwtAuthorizationProvider authorizationProvider;
 	    private final JwtAuthcOrAuthzFailureHandler authenticationFailureHandler;
	    
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
		
		public JwtAuthzWebSecurityConfigurerAdapter(
				
				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
   				ObjectProvider<ObjectMapper> objectMapperProvider,
   				ObjectProvider<SessionRegistry> sessionRegistryProvider,
   				ObjectProvider<RememberMeServices> rememberMeServicesProvider,
   				
   				SecurityJwtAuthcProperties jwtAuthcProperties,
   				SecurityJwtAuthzProperties jwtAuthzProperties,
   				ObjectProvider<JwtAuthorizationProvider> authenticationProvider,
   				ObjectProvider<JwtAuthcOrAuthzFailureHandler> authenticationFailureHandler,
   				
   				@Qualifier("idcAuthenticatingFailureCounter") ObjectProvider<AuthenticatingFailureCounter> authenticatingFailureCounter,
   				@Qualifier("idcCsrfTokenRepository") ObjectProvider<CsrfTokenRepository> csrfTokenRepositoryProvider,
   				@Qualifier("idcInvalidSessionStrategy") ObjectProvider<InvalidSessionStrategy> invalidSessionStrategyProvider,
				@Qualifier("idcRequestCache") ObjectProvider<RequestCache> requestCacheProvider,
				@Qualifier("idcSecurityContextLogoutHandler")  ObjectProvider<SecurityContextLogoutHandler> securityContextLogoutHandlerProvider,
				@Qualifier("idcSessionAuthenticationStrategy") ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider,
				@Qualifier("idcExpiredSessionStrategy") ObjectProvider<SessionInformationExpiredStrategy> expiredSessionStrategyProvider
				
				) {
			
			this.authenticationManager = authenticationManagerProvider.getIfAvailable();
   			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
   			
   			this.jwtAuthcProperties = jwtAuthcProperties;
   			this.jwtAuthzProperties = jwtAuthzProperties;
   			
   			this.authorizationProvider = authenticationProvider.getIfAvailable();
   			this.authenticationFailureHandler = authenticationFailureHandler.getIfAvailable();
   			
   			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
   			
		}

		@Bean
	    public JwtAuthorizationProcessingFilter authorizationProcessingFilter() {
	    	
	    	JwtAuthorizationProcessingFilter authcFilter = new JwtAuthorizationProcessingFilter();
			
			authcFilter.setAllowSessionCreation(jwtAuthzProperties.isAllowSessionCreation());
			authcFilter.setApplicationEventPublisher(eventPublisher);
			authcFilter.setAuthenticationFailureHandler(authenticationFailureHandler);
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
			if (StringUtils.hasText(jwtAuthcProperties.getLoginUrlPatterns())) {
				authcFilter.setLoginFilterProcessesUrl(jwtAuthcProperties.getLoginUrlPatterns());
			}
			authcFilter.setAuthorizationCookieName(jwtAuthzProperties.getAuthorizationCookieName());
			authcFilter.setAuthorizationHeaderName(jwtAuthzProperties.getAuthorizationHeaderName());
			authcFilter.setAuthorizationParamName(jwtAuthzProperties.getAuthorizationParamName());
			authcFilter.setRememberMeServices(rememberMeServices);
			authcFilter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
			
	        return authcFilter;
	    }
		
		@Override
	    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	        auth.authenticationProvider(authorizationProvider);
	    }

	    @Override
	    protected void configure(HttpSecurity http) throws Exception {
	    	http.csrf().disable(); // We don't need CSRF for JWT based authentication
	    	http.addFilterBefore(authorizationProcessingFilter(), UsernamePasswordAuthenticationFilter.class);
	    }

		@Override
		public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
			this.eventPublisher = applicationEventPublisher;
		}
		
	}

}
