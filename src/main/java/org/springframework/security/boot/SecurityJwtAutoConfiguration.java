package org.springframework.security.boot;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.jwt.authentication.JwtMatchedAuthcOrAuthzFailureHandler;
import org.springframework.security.boot.jwt.authentication.JwtMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.jwt.authentication.JwtMatchedAuthenticationSuccessHandler;

@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@EnableConfigurationProperties({ SecurityBizProperties.class, SecurityJwtProperties.class })
public class SecurityJwtAutoConfiguration {
	
	@Autowired
	private SecurityBizProperties bizProperties;
	@Autowired
	private SecurityJwtProperties jwtProperties;
	
	@Bean("jwtAuthenticationSuccessHandler")
	public PostRequestAuthenticationSuccessHandler jwtAuthenticationSuccessHandler(
			@Autowired(required = false) List<AuthenticationListener> authenticationListeners,
			@Autowired(required = false) List<MatchedAuthenticationSuccessHandler> successHandlers) {
		
		PostRequestAuthenticationSuccessHandler successHandler = new PostRequestAuthenticationSuccessHandler(
				authenticationListeners, successHandlers);
		
		successHandler.setDefaultTargetUrl(jwtProperties.getAuthc().getSuccessUrl());
		successHandler.setStateless(bizProperties.isStateless());
		successHandler.setTargetUrlParameter(jwtProperties.getAuthc().getTargetUrlParameter());
		successHandler.setUseReferer(jwtProperties.getAuthc().isUseReferer());
		
		return successHandler;
	}
	
	@Bean
	@ConditionalOnMissingBean
	public JwtMatchedAuthcOrAuthzFailureHandler jwtMatchedAuthcOrAuthzFailureHandler() {
		return new JwtMatchedAuthcOrAuthzFailureHandler();
	}
	
	@Bean
	@ConditionalOnMissingBean
	public JwtMatchedAuthenticationEntryPoint jwtMatchedAuthenticationEntryPoint() {
		return new JwtMatchedAuthenticationEntryPoint();
	}

	@Bean
	@ConditionalOnMissingBean
	public JwtMatchedAuthenticationSuccessHandler jwtMatchedAuthenticationSuccessHandler(JwtPayloadRepository payloadRepository) {
		return new JwtMatchedAuthenticationSuccessHandler(payloadRepository);
	}

}
