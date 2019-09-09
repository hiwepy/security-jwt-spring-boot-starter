package org.springframework.security.boot;

import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.biz.authentication.AuthenticatingFailureCounter;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationProcessingFilter;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationProvider;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationSuccessHandler;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.util.CollectionUtils;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
@AutoConfigureBefore({ SecurityFilterAutoConfiguration.class })
@ConditionalOnProperty(prefix = SecurityJwtAuthzProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityBizProperties.class, SecurityJwtProperties.class, SecurityJwtAuthcProperties.class, SecurityJwtAuthzProperties.class })
public class SecurityJwtAuthzFilterConfiguration {

	@Bean
	@ConditionalOnMissingBean
	public JwtAuthorizationProvider jwtAuthorizationProvider(JwtPayloadRepository payloadRepository) {
		return new JwtAuthorizationProvider(payloadRepository);
	}
	
	@Bean
	public JwtAuthorizationSuccessHandler jwtAuthorizationSuccessHandler() {
		return new JwtAuthorizationSuccessHandler();
	}
    
    @Configuration
    @ConditionalOnProperty(prefix = SecurityJwtAuthzProperties.PREFIX, value = "enabled", havingValue = "true")
	@EnableConfigurationProperties({ SecurityBizProperties.class, SecurityJwtProperties.class, SecurityJwtAuthcProperties.class, SecurityJwtAuthzProperties.class })
    @Order(107)
	static class JwtAuthzWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter implements ApplicationEventPublisherAware {

    	private ApplicationEventPublisher eventPublisher;
    	
    	private final AuthenticationManager authenticationManager;
	    private final RememberMeServices rememberMeServices;
	    
		private final SecurityBizProperties bizProperties;
		private final SecurityJwtAuthcProperties jwtAuthcProperties;
    	private final SecurityJwtAuthzProperties jwtAuthzProperties;
 	    private final JwtAuthorizationProvider authorizationProvider;
	    private final JwtAuthorizationSuccessHandler authorizationSuccessHandler;
	    private final PostRequestAuthenticationFailureHandler authorizationFailureHandler;
	    
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
		
		public JwtAuthzWebSecurityConfigurerAdapter(
				
				SecurityBizProperties bizProperties,
   				SecurityJwtAuthcProperties jwtAuthcProperties,
   				SecurityJwtAuthzProperties jwtAuthzProperties,
   				
				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
				ObjectProvider<AuthenticatingFailureCounter> authenticatingFailureCounter,
   				ObjectProvider<JwtAuthorizationProvider> authenticationProvider,
   				ObjectProvider<JwtAuthorizationSuccessHandler> authorizationSuccessHandler,
   				ObjectProvider<InvalidSessionStrategy> invalidSessionStrategyProvider,
   				ObjectProvider<ObjectMapper> objectMapperProvider,
				ObjectProvider<RequestCache> requestCacheProvider,
				ObjectProvider<RememberMeServices> rememberMeServicesProvider,
				ObjectProvider<PostRequestAuthenticationFailureHandler> authorizationFailureHandler,
				ObjectProvider<SessionRegistry> sessionRegistryProvider,
				ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider,
   				
				@Qualifier("jwtSecurityContextLogoutHandler")  ObjectProvider<SecurityContextLogoutHandler> securityContextLogoutHandlerProvider
				
			) {
			
			this.authenticationManager = authenticationManagerProvider.getIfAvailable();
   			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
   			
   			this.bizProperties = bizProperties;
   			this.jwtAuthcProperties = jwtAuthcProperties;
   			this.jwtAuthzProperties = jwtAuthzProperties;
   			
   			this.authorizationProvider = authenticationProvider.getIfAvailable();
   			this.authorizationSuccessHandler = authorizationSuccessHandler.getIfAvailable();
   			this.authorizationFailureHandler = authorizationFailureHandler.getIfAvailable();
   			
   			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
   			
		}

		@Bean
	    public JwtAuthorizationProcessingFilter jwtAuthorizationProcessingFilter() {
	    	
	    	JwtAuthorizationProcessingFilter authzFilter = new JwtAuthorizationProcessingFilter();
			
			authzFilter.setAllowSessionCreation(bizProperties.getSessionMgt().isAllowSessionCreation());
			authzFilter.setApplicationEventPublisher(eventPublisher);
			authzFilter.setAuthenticationFailureHandler(authorizationFailureHandler);
			authzFilter.setAuthenticationManager(authenticationManager);
			authzFilter.setAuthenticationSuccessHandler(authorizationSuccessHandler);
			authzFilter.setContinueChainBeforeSuccessfulAuthentication(jwtAuthzProperties.isContinueChainBeforeSuccessfulAuthentication());
			if (StringUtils.hasText(jwtAuthzProperties.getPathPattern())) {
				authzFilter.setFilterProcessesUrl(jwtAuthzProperties.getPathPattern());
			}
			authzFilter.setAuthorizationCookieName(jwtAuthzProperties.getAuthorizationCookieName());
			authzFilter.setAuthorizationHeaderName(jwtAuthzProperties.getAuthorizationHeaderName());
			authzFilter.setAuthorizationParamName(jwtAuthzProperties.getAuthorizationParamName());
			
			// 对过滤链按过滤器名称进行分组
			List<Entry<String, String>> noneEntries = bizProperties.getFilterChainDefinitionMap().entrySet().stream()
					.filter(predicate -> {
						return "anon".equalsIgnoreCase(predicate.getValue());
					}).collect(Collectors.toList());
   			
   			List<String> ignorePatterns = new ArrayList<String>();
   			if (!CollectionUtils.isEmpty(noneEntries)) {
   				ignorePatterns = noneEntries.stream().map(mapper -> {
   					return mapper.getKey();
   				}).collect(Collectors.toList());
   			}
   			// 登录地址不拦截 
   			ignorePatterns.add(jwtAuthcProperties.getLoginUrlPatterns());
			authzFilter.setIgnoreRequestMatcher(ignorePatterns);
			authzFilter.setRememberMeServices(rememberMeServices);
			authzFilter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
			
	        return authzFilter;
	    }
		
		@Override
	    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	        auth.authenticationProvider(authorizationProvider);
	    }

	    @Override
	    protected void configure(HttpSecurity http) throws Exception {
	    	http.csrf().disable(); // We don't need CSRF for JWT based authentication
	    	// 禁用缓存
	    	http.headers().cacheControl();
	    	// 添加JWT filter
	    	http.addFilterBefore(jwtAuthorizationProcessingFilter(), UsernamePasswordAuthenticationFilter.class);
	    }
	    
	    @Override
   	    public void configure(WebSecurity web) throws Exception {
   	    	web.ignoring()
   	    		.antMatchers(jwtAuthcProperties.getLoginUrlPatterns())
   	    		.antMatchers(jwtAuthzProperties.getPathPattern())
   	    		.antMatchers(HttpMethod.OPTIONS, "/**");
   	    }

		@Override
		public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
			this.eventPublisher = applicationEventPublisher;
		}
		
	}

}
