package org.springframework.security.boot;

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
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.biz.authentication.AuthenticatingFailureCounter;
import org.springframework.security.boot.biz.authentication.AuthenticatingFailureRequestCounter;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.authentication.captcha.CaptchaResolver;
import org.springframework.security.boot.biz.authentication.captcha.NullCaptchaResolver;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationProcessingFilter;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationProvider;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.vindell.jwt.JwtPayload;

@Configuration
@AutoConfigureBefore({ SecurityFilterAutoConfiguration.class })
@ConditionalOnProperty(prefix = SecurityJwtAuthcProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityJwtProperties.class, SecurityJwtAuthcProperties.class })
public class SecurityJwtAuthcFilterConfiguration {

    /*
	 *################################################################### 
	 *# Jwt认证 (authentication) 配置
	 *###################################################################
	 */

    @Bean
	@ConditionalOnMissingBean 
	public CaptchaResolver captchaResolver() {
		return new NullCaptchaResolver();
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
	
	@Configuration
	@ConditionalOnProperty(prefix = SecurityJwtAuthcProperties.PREFIX, value = "enabled", havingValue = "true")
	@EnableConfigurationProperties({ SecurityJwtProperties.class, SecurityBizProperties.class })
    @Order(106)
	static class JwtAuthcWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter implements ApplicationEventPublisherAware {

    	private ApplicationEventPublisher eventPublisher;
    	
    	private final AuthenticationManager authenticationManager;
	    private final ObjectMapper objectMapper;
	    private final RememberMeServices rememberMeServices;
	    
	    private final SecurityBizProperties bizProperties;
		private final SecurityJwtAuthcProperties jwtAuthcProperties;
 	    private final JwtAuthenticationProvider authenticationProvider;
 	    private final PostRequestAuthenticationSuccessHandler authenticationSuccessHandler;
	    private final PostRequestAuthenticationFailureHandler authenticationFailureHandler;
 	    private final CaptchaResolver captchaResolver;

		private final AuthenticatingFailureCounter authenticatingFailureCounter;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
		
		public JwtAuthcWebSecurityConfigurerAdapter(
				
				SecurityBizProperties bizProperties,
   				SecurityJwtProperties jwtProperties,
   				SecurityJwtAuthcProperties jwtAuthcProperties,
   				
				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
				ObjectProvider<AuthenticatingFailureCounter> authenticatingFailureCounter,
   				ObjectProvider<CaptchaResolver> captchaResolverProvider,
   				ObjectProvider<JwtAuthenticationProvider> authenticationProvider,
   				ObjectProvider<ObjectMapper> objectMapperProvider,
   				ObjectProvider<PostRequestAuthenticationFailureHandler> authenticationFailureHandler,
   				ObjectProvider<RememberMeServices> rememberMeServicesProvider,
   				ObjectProvider<SessionRegistry> sessionRegistryProvider,
   				ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider,
   				
   				@Qualifier("jwtAuthenticationSuccessHandler") ObjectProvider<PostRequestAuthenticationSuccessHandler> authenticationSuccessHandler
   			) {
		    
			
			this.authenticationManager = authenticationManagerProvider.getIfAvailable();
   			this.objectMapper = objectMapperProvider.getIfAvailable();
   			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
   			
   			this.bizProperties = bizProperties;
   			this.jwtAuthcProperties = jwtAuthcProperties;
   			this.authenticationProvider = authenticationProvider.getIfAvailable();
   			this.authenticationSuccessHandler = authenticationSuccessHandler.getIfAvailable();
   			this.authenticationFailureHandler = authenticationFailureHandler.getIfAvailable();
   			this.captchaResolver = captchaResolverProvider.getIfAvailable();
   			
   			this.authenticatingFailureCounter = authenticatingFailureCounter.getIfAvailable();
   			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
   			
		}


	    @Bean
		public JwtAuthenticationProcessingFilter jwtAuthenticationProcessingFilter() throws Exception {
	    	
	        JwtAuthenticationProcessingFilter authcFilter = new JwtAuthenticationProcessingFilter(objectMapper);
	        
	        authcFilter.setCaptchaParameter(jwtAuthcProperties.getCaptcha().getParamName());
			// 是否验证码必填
			authcFilter.setCaptchaRequired(jwtAuthcProperties.getCaptcha().isRequired());
			// 登陆失败重试次数，超出限制需要输入验证码
			authcFilter.setRetryTimesWhenAccessDenied(jwtAuthcProperties.getCaptcha().getRetryTimesWhenAccessDenied());
			// 验证码解析器
			authcFilter.setCaptchaResolver(captchaResolver);
			// 认证失败计数器
			authcFilter.setFailureCounter(authenticatingFailureCounter);

			authcFilter.setAllowSessionCreation(bizProperties.getSessionMgt().isAllowSessionCreation());
			authcFilter.setApplicationEventPublisher(eventPublisher);
			authcFilter.setAuthenticationFailureHandler(authenticationFailureHandler);
			authcFilter.setAuthenticationManager(authenticationManager);
			authcFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
			authcFilter.setContinueChainBeforeSuccessfulAuthentication(jwtAuthcProperties.isContinueChainBeforeSuccessfulAuthentication());
			if (StringUtils.hasText(jwtAuthcProperties.getLoginUrlPatterns())) {
				authcFilter.setFilterProcessesUrl(jwtAuthcProperties.getLoginUrlPatterns());
			}
			//authcFilter.setMessageSource(messageSource);
			authcFilter.setUsernameParameter(jwtAuthcProperties.getUsernameParameter());
			authcFilter.setPasswordParameter(jwtAuthcProperties.getPasswordParameter());
			authcFilter.setPostOnly(jwtAuthcProperties.isPostOnly());
			authcFilter.setRememberMeServices(rememberMeServices);
			authcFilter.setRetryTimesKeyAttribute(jwtAuthcProperties.getRetryTimesKeyAttribute());
			authcFilter.setRetryTimesWhenAccessDenied(jwtAuthcProperties.getRetryTimesWhenAccessDenied());
			authcFilter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
			
	        return authcFilter;
	    }
		
		@Override
	    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	        auth.authenticationProvider(authenticationProvider);
	    }

	    @Override
	    protected void configure(HttpSecurity http) throws Exception {
	    	http.csrf().disable(); // We don't need CSRF for JWT based authentication
	    	http.addFilterBefore(jwtAuthenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class);
	    }
	    
	    @Override
   	    public void configure(WebSecurity web) throws Exception {
   	    	web.ignoring().antMatchers(jwtAuthcProperties.getLoginUrlPatterns());
   	    }

		@Override
		public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
			this.eventPublisher = applicationEventPublisher;
		}
		
	}

}
