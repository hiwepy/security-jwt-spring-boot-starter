package org.springframework.security.boot;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import org.springframework.beans.factory.ObjectProvider;
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
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.boot.biz.JsonInvalidSessionStrategy;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationProcessingFilter;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationProvider;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationSuccessHandler;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.util.CollectionUtils;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
@AutoConfigureBefore({ SecurityFilterAutoConfiguration.class })
@ConditionalOnProperty(prefix = SecurityJwtAuthzProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityBizProperties.class, SecurityJwtAuthcProperties.class, SecurityJwtAuthzProperties.class })
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
	@EnableConfigurationProperties({ SecurityBizProperties.class, SecurityJwtAuthcProperties.class, SecurityJwtAuthzProperties.class })
    @Order(SecurityProperties.DEFAULT_FILTER_ORDER + 80)
	static class JwtAuthzWebSecurityConfigurerAdapter extends SecurityBizConfigurerAdapter {

    	private final SecurityBizProperties bizProperties;
    	private final SecurityJwtAuthcProperties jwtAuthcProperties;
    	private final SecurityJwtAuthzProperties authzProperties;
    	
    	private final AuthenticationManager authenticationManager;	
 	    private final JwtAuthorizationProvider authorizationProvider;
 	    private final JwtAuthorizationSuccessHandler authorizationSuccessHandler;
 	    private final PostRequestAuthenticationFailureHandler authorizationFailureHandler;
 	    private final InvalidSessionStrategy invalidSessionStrategy;
     	private final RequestCache requestCache;
     	private final RememberMeServices rememberMeServices;
     	private final SessionRegistry sessionRegistry;
 		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
 		private final SessionInformationExpiredStrategy sessionInformationExpiredStrategy;
		
		public JwtAuthzWebSecurityConfigurerAdapter(
				
				SecurityBizProperties bizProperties,
   				SecurityJwtAuthcProperties jwtAuthcProperties,
   				SecurityJwtAuthzProperties jwtAuthzProperties,
   				
   				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
   				ObjectProvider<JwtAuthorizationProvider> authorizationProvider,
   				ObjectProvider<PostRequestAuthenticationFailureHandler> authorizationFailureHandler,
   				ObjectProvider<JwtAuthorizationSuccessHandler> authorizationSuccessHandler,
   				ObjectProvider<CsrfTokenRepository> csrfTokenRepositoryProvider,
   				@Qualifier("jwtLogoutHandler") ObjectProvider<SecurityContextLogoutHandler> logoutHandlerProvider,
   				ObjectProvider<ObjectMapper> objectMapperProvider,
				ObjectProvider<RequestCache> requestCacheProvider,
				ObjectProvider<RememberMeServices> rememberMeServicesProvider,
				ObjectProvider<SessionRegistry> sessionRegistryProvider,
				ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider,
				ObjectProvider<SessionInformationExpiredStrategy> sessionInformationExpiredStrategyProvider
				
			) {
			
			super(bizProperties, csrfTokenRepositoryProvider.getIfAvailable());
			
   			this.bizProperties = bizProperties;
   			this.jwtAuthcProperties = jwtAuthcProperties;
   			this.authzProperties = jwtAuthzProperties;
   			
   			this.authenticationManager = authenticationManagerProvider.getIfAvailable();
   			this.authorizationProvider = authorizationProvider.getIfAvailable();
   			this.authorizationFailureHandler = authorizationFailureHandler.getIfAvailable();
   			this.authorizationSuccessHandler = authorizationSuccessHandler.getIfAvailable();
   			this.invalidSessionStrategy = new JsonInvalidSessionStrategy();
   			this.requestCache = requestCacheProvider.getIfAvailable();
   			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
   			this.sessionRegistry = sessionRegistryProvider.getIfAvailable();
   			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
   			this.sessionInformationExpiredStrategy = sessionInformationExpiredStrategyProvider.getIfAvailable();
   			
		}
		
		@Override
		public AuthenticationManager authenticationManagerBean() throws Exception {
   			AuthenticationManager parentManager = authenticationManager == null ? super.authenticationManagerBean() : authenticationManager;
			ProviderManager authenticationManager = new ProviderManager( Arrays.asList(authorizationProvider), parentManager);
			// 不擦除认证密码，擦除会导致TokenBasedRememberMeServices因为找不到Credentials再调用UserDetailsService而抛出UsernameNotFoundException
			authenticationManager.setEraseCredentialsAfterAuthentication(false);
			return authenticationManager;
		}

	    public JwtAuthorizationProcessingFilter authenticationProcessingFilter() throws Exception {
	    	
	    	JwtAuthorizationProcessingFilter authenticationFilter = new JwtAuthorizationProcessingFilter();
			
	    	/**
			 * 批量设置参数
			 */
			PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
			
			
			map.from(bizProperties.getSessionMgt().isAllowSessionCreation()).to(authenticationFilter::setAllowSessionCreation);
			map.from(authenticationManagerBean()).to(authenticationFilter::setAuthenticationManager);
			map.from(authorizationSuccessHandler).to(authenticationFilter::setAuthenticationSuccessHandler);
			map.from(authorizationFailureHandler).to(authenticationFilter::setAuthenticationFailureHandler);
			map.from(authzProperties.getAuthorizationCookieName()).to(authenticationFilter::setAuthorizationCookieName);
			map.from(authzProperties.getAuthorizationHeaderName()).to(authenticationFilter::setAuthorizationHeaderName);
			map.from(authzProperties.getAuthorizationParamName()).to(authenticationFilter::setAuthorizationParamName);
			map.from(authzProperties.getPathPattern()).to(authenticationFilter::setFilterProcessesUrl);
			map.from(rememberMeServices).to(authenticationFilter::setRememberMeServices);
			map.from(sessionAuthenticationStrategy).to(authenticationFilter::setSessionAuthenticationStrategy);
			map.from(authzProperties.isContinueChainBeforeSuccessfulAuthentication()).to(authenticationFilter::setContinueChainBeforeSuccessfulAuthentication);
			
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
   			ignorePatterns.add(jwtAuthcProperties.getPathPattern());
			authenticationFilter.setIgnoreRequestMatcher(ignorePatterns);
			
	        return authenticationFilter;
	    }
		
		@Override
		public void configure(AuthenticationManagerBuilder auth) throws Exception {
	        auth.authenticationProvider(authorizationProvider);
	        super.configure(auth);
	    }

	    @Override
		public void configure(HttpSecurity http) throws Exception {
	    	
	    	// Session 管理器配置参数
   	    	SecuritySessionMgtProperties sessionMgt = bizProperties.getSessionMgt();
   	    	
   		    // Session 管理器配置
   	    	http.sessionManagement()
   	    		.enableSessionUrlRewriting(sessionMgt.isEnableSessionUrlRewriting())
   	    		.invalidSessionStrategy(invalidSessionStrategy)
   	    		.maximumSessions(sessionMgt.getMaximumSessions())
   	    		.maxSessionsPreventsLogin(sessionMgt.isMaxSessionsPreventsLogin())
   	    		.expiredSessionStrategy(sessionInformationExpiredStrategy)
   				.sessionRegistry(sessionRegistry)
   				.and()
   	    		.sessionAuthenticationErrorUrl(sessionMgt.getFailureUrl())
   	    		.sessionAuthenticationFailureHandler(authorizationFailureHandler)
   	    		.sessionAuthenticationStrategy(sessionAuthenticationStrategy)
   	    		.sessionCreationPolicy(sessionMgt.getCreationPolicy())
   	        	// Request 缓存配置
   	        	.and()
   	    		.requestCache()
   	        	.requestCache(requestCache)
   	        	.and()
   	        	.antMatcher(authzProperties.getPathPattern())
   	        	.addFilterBefore(authenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class); 

   	    	super.configure(http, authzProperties.getCros());
   	    	super.configure(http, authzProperties.getCsrf());
   	    	super.configure(http, authzProperties.getHeaders());
	    	super.configure(http);
	    }
	    
	    @Override
	    public void configure(WebSecurity web) throws Exception {
	    }
	    
	}

}
