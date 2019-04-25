package org.springframework.security.boot;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.userdetails.BaseAuthenticationUserDetailsService;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationEntryPoint;
import org.springframework.security.boot.jwt.authentication.JwtAuthcOrAuthzFailureHandler;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationProvider;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationSuccessHandler;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationProvider;
import org.springframework.security.boot.jwt.userdetails.JwtPayloadRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.NullRememberMeServices;
import org.springframework.security.web.authentication.RememberMeServices;

@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityJwtProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityJwtProperties.class })
public class SecurityJwtAutoConfiguration{

	@Autowired
	private SecurityBizProperties bizProperties;
	
	@Bean
	public RememberMeServices rememberMeServices() {
		return new NullRememberMeServices();
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
		failureHandler.setAllowSessionCreation(bizProperties.getSessionMgt().isAllowSessionCreation());
		failureHandler.setRedirectStrategy(redirectStrategy);
		failureHandler.setUseForward(bizProperties.getAuthc().isUseForward());
		return failureHandler;
	}

	@Bean
	public JwtAuthorizationProvider jwtAuthorizationProvider(BaseAuthenticationUserDetailsService userDetailsService) {
		return new JwtAuthorizationProvider(userDetailsService);
	}

}
