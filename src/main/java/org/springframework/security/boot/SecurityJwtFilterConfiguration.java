package org.springframework.security.boot;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
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
import org.springframework.security.boot.biz.authentication.captcha.CaptchaResolver;
import org.springframework.security.boot.jwt.authentication.JwtAuthcOrAuthzFailureHandler;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationEntryPoint;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationProcessingFilter;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationProvider;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationSuccessHandler;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationProcessingFilter;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationProvider;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
@AutoConfigureAfter(SecurityBizFilterAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityJwtProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityJwtProperties.class })
@Order(103)
public class SecurityJwtFilterConfiguration extends WebSecurityConfigurerAdapter  implements ApplicationEventPublisherAware {

	private ApplicationEventPublisher eventPublisher;
	
	@Autowired
	private SecurityJwtProperties jwtProperties;
	@Autowired
	private AuthenticatingFailureCounter authenticatingFailureCounter;
	@Autowired
	private AuthenticationManager authenticationManager;
	@Autowired
	private JwtAuthenticationSuccessHandler successHandler;
	@Autowired
	private JwtAuthcOrAuthzFailureHandler failureHandler;
	@Autowired
	private RememberMeServices rememberMeServices;
	@Autowired
	private SessionAuthenticationStrategy sessionStrategy;
    @Autowired(required = false) 
    private CaptchaResolver captchaResolver;
    @Autowired
	private  ObjectMapper objectMapper;
    @Autowired
    private JwtAuthenticationProvider jwtAuthenticationProvider;
    @Autowired
    private JwtAuthenticationEntryPoint authenticationEntryPoint;
    @Autowired
    private JwtAuthorizationProvider jwtAuthorizationProvider;
    
    @Bean
	public JwtAuthenticationProcessingFilter jwtAuthenticationProcessingFilter() throws Exception {
    	
        JwtAuthenticationProcessingFilter authcFilter = new JwtAuthenticationProcessingFilter(objectMapper);
        
        authcFilter.setCaptchaParameter(jwtProperties.getCaptcha().getParamName());
		// 是否验证码必填
		authcFilter.setCaptchaRequired(jwtProperties.getCaptcha().isRequired());
		// 登陆失败重试次数，超出限制需要输入验证码
		authcFilter.setRetryTimesWhenAccessDenied(jwtProperties.getCaptcha().getRetryTimesWhenAccessDenied());
		// 验证码解析器
		authcFilter.setCaptchaResolver(captchaResolver);
		// 认证失败计数器
		authcFilter.setFailureCounter(authenticatingFailureCounter);

		authcFilter.setAllowSessionCreation(jwtProperties.getSessionMgt().isAllowSessionCreation());
		authcFilter.setApplicationEventPublisher(eventPublisher);
		authcFilter.setAuthenticationFailureHandler(failureHandler);
		authcFilter.setAuthenticationManager(authenticationManager);
		authcFilter.setAuthenticationSuccessHandler(successHandler);
		authcFilter.setContinueChainBeforeSuccessfulAuthentication(jwtProperties.getAuthc().isContinueChainBeforeSuccessfulAuthentication());
		if (StringUtils.hasText(jwtProperties.getAuthc().getLoginUrlPattern())) {
			authcFilter.setFilterProcessesUrl(jwtProperties.getAuthc().getLoginUrlPattern());
		}
		//authcFilter.setMessageSource(messageSource);
		authcFilter.setUsernameParameter(jwtProperties.getAuthc().getUsernameParameter());
		authcFilter.setPasswordParameter(jwtProperties.getAuthc().getPasswordParameter());
		authcFilter.setPostOnly(jwtProperties.getAuthc().isPostOnly());
		authcFilter.setRememberMeServices(rememberMeServices);
		authcFilter.setRetryTimesKeyAttribute(jwtProperties.getAuthc().getRetryTimesKeyAttribute());
		authcFilter.setRetryTimesWhenAccessDenied(jwtProperties.getAuthc().getRetryTimesWhenAccessDenied());
		authcFilter.setSessionAuthenticationStrategy(sessionStrategy);
		
        return authcFilter;
    }
    
    @Bean
    public JwtAuthorizationProcessingFilter jwtAuthorizationProcessingFilter() {
    	
    	JwtAuthorizationProcessingFilter authcFilter = new JwtAuthorizationProcessingFilter();
		
		authcFilter.setAllowSessionCreation(jwtProperties.getAuthz().isAllowSessionCreation());
		authcFilter.setApplicationEventPublisher(eventPublisher);
		authcFilter.setAuthenticationFailureHandler(failureHandler);
		authcFilter.setAuthenticationManager(authenticationManager);
		authcFilter.setAuthenticationSuccessHandler(new AuthenticationSuccessHandler() {
			public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
					Authentication authentication) throws IOException, ServletException {
				// no-op - just allow filter chain to continue to token endpoint
			}
		});
		authcFilter.setContinueChainBeforeSuccessfulAuthentication(jwtProperties.getAuthz().isContinueChainBeforeSuccessfulAuthentication());
		if (StringUtils.hasText(jwtProperties.getAuthz().getPathPattern())) {
			authcFilter.setFilterProcessesUrl(jwtProperties.getAuthz().getPathPattern());
		}
		if (StringUtils.hasText(jwtProperties.getAuthc().getLoginUrlPattern())) {
			authcFilter.setLoginFilterProcessesUrl(jwtProperties.getAuthc().getLoginUrlPattern());
		}
		authcFilter.setAuthorizationCookieName(jwtProperties.getAuthz().getAuthorizationCookieName());
		authcFilter.setAuthorizationHeaderName(jwtProperties.getAuthz().getAuthorizationHeaderName());
		authcFilter.setAuthorizationParamName(jwtProperties.getAuthz().getAuthorizationParamName());
		authcFilter.setRememberMeServices(rememberMeServices);
		authcFilter.setSessionAuthenticationStrategy(sessionStrategy);
		
        return authcFilter;
    }
 
	 
    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(jwtAuthenticationProvider)
        	.authenticationProvider(jwtAuthorizationProvider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable() // We don't need CSRF for JWT based authentication
				.exceptionHandling().authenticationEntryPoint(this.authenticationEntryPoint)
				.and()
				.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.and()
				.addFilterBefore(jwtAuthenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
				.addFilterBefore(jwtAuthorizationProcessingFilter(), UsernamePasswordAuthenticationFilter.class);
    }

	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
		this.eventPublisher = applicationEventPublisher;
	}

}
