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
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.biz.authentication.AuthenticatingFailureCounter;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationProcessingFilter;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationProvider;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationSuccessHandler;
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
	static class JwtAuthzWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

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

	    public JwtAuthorizationProcessingFilter authenticationProcessingFilter() {
	    	
	    	JwtAuthorizationProcessingFilter authenticationFilter = new JwtAuthorizationProcessingFilter();
			
	    	/**
			 * 批量设置参数
			 */
			PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
			
			map.from(bizProperties.getSessionMgt().isAllowSessionCreation()).to(authenticationFilter::setAllowSessionCreation);
			map.from(authenticationManager).to(authenticationFilter::setAuthenticationManager);
			map.from(authorizationSuccessHandler).to(authenticationFilter::setAuthenticationSuccessHandler);
			map.from(authorizationFailureHandler).to(authenticationFilter::setAuthenticationFailureHandler);
			map.from(jwtAuthzProperties.getAuthorizationCookieName()).to(authenticationFilter::setAuthorizationCookieName);
			map.from(jwtAuthzProperties.getAuthorizationHeaderName()).to(authenticationFilter::setAuthorizationHeaderName);
			map.from(jwtAuthzProperties.getAuthorizationParamName()).to(authenticationFilter::setAuthorizationParamName);
			map.from(jwtAuthzProperties.getPathPattern()).to(authenticationFilter::setFilterProcessesUrl);
			map.from(rememberMeServices).to(authenticationFilter::setRememberMeServices);
			map.from(sessionAuthenticationStrategy).to(authenticationFilter::setSessionAuthenticationStrategy);
			map.from(jwtAuthzProperties.isContinueChainBeforeSuccessfulAuthentication()).to(authenticationFilter::setContinueChainBeforeSuccessfulAuthentication);
			
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
	    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	        auth.authenticationProvider(authorizationProvider);
	    }

	    @Override
	    protected void configure(HttpSecurity http) throws Exception {
	    	http.csrf().disable(); // We don't need CSRF for JWT based authentication
	    	// 禁用缓存
	    	http.headers().cacheControl();
	    	// 添加JWT filter
	    	http.addFilterBefore(authenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class);
	    }
	    
	    @Override
   	    public void configure(WebSecurity web) throws Exception {
   	    	web.ignoring()
   	    		.antMatchers(jwtAuthcProperties.getPathPattern());
   	    }

	}

}
