package org.springframework.security.boot;

import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.biz.filter.CustomCorsFilter;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationProcessingFilter;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationProvider;
import org.springframework.security.boot.jwt.authentication.JwtRequestAuthenticationProvider;
import org.springframework.security.boot.jwt.authentication.jwt.JwtTokenAuthenticationFilter;
import org.springframework.security.boot.jwt.authentication.jwt.SkipPathRequestMatcher;
import org.springframework.security.boot.jwt.authentication.jwt.extractor.TokenExtractor;
import org.springframework.security.boot.jwt.endpoint.RestAuthenticationEntryPoint;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.NullRememberMeServices;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
@AutoConfigureAfter(SecurityBizFilterAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityJwtProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityJwtProperties.class, SecurityBizProperties.class, ServerProperties.class })
public class SecurityJwtWebFilterConfiguration extends WebSecurityConfigurerAdapter implements ApplicationContextAware {

	private ApplicationContext applicationContext;

	@Autowired
	private SecurityJwtProperties jwtProperties;
	@Autowired
	private SecurityBizProperties bizProperties;
	@Autowired
	private ServerProperties serverProperties;

 
	@Bean
	@ConditionalOnMissingBean
	public SessionAuthenticationStrategy sessionStrategy() {
		return new NullAuthenticatedSessionStrategy();
	}

	@Bean
	@ConditionalOnMissingBean
	public RememberMeServices rememberMeServices() {
		return new NullRememberMeServices();
	}
 
    @Bean
	@ConditionalOnMissingBean
	public ObjectMapper objectMapper() {
		return new ObjectMapper();
	}
    
    @Bean
	@ConditionalOnMissingBean
	public JwtAuthenticationProcessingFilter jwtAjaxLoginProcessingFilter(AuthenticationFailureHandler failureHandler,
			AuthenticationManager authenticationManager, ApplicationEventPublisher publisher,
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource,
			AuthenticationSuccessHandler successHandler, RememberMeServices rememberMeServices,
			SessionAuthenticationStrategy sessionStrategy, ObjectMapper objectMapper) throws Exception {
        //AjaxUsernamePasswordAuthenticationFilter filter = new AjaxUsernamePasswordAuthenticationFilter(FORM_BASED_LOGIN_ENTRY_POINT, successHandler, failureHandler, objectMapper);
        //filter.setAuthenticationManager(authenticationManager);
        return null;
    }
    
    @Bean
	@ConditionalOnMissingBean
	public JwtTokenAuthenticationFilter jwtTokenAuthenticationProcessingFilter(
    		AuthenticationFailureHandler failureHandler,
    		TokenExtractor tokenExtractor,
			AuthenticationManager authenticationManager, ApplicationEventPublisher publisher,
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource,
			AuthenticationSuccessHandler successHandler, RememberMeServices rememberMeServices,
			SessionAuthenticationStrategy sessionStrategy) throws Exception {
    	
        List<String> pathsToSkip = Arrays.asList(TOKEN_REFRESH_ENTRY_POINT, FORM_BASED_LOGIN_ENTRY_POINT);
        SkipPathRequestMatcher matcher = new SkipPathRequestMatcher(pathsToSkip, TOKEN_BASED_AUTH_ENTRY_POINT);
        
        JwtTokenAuthenticationFilter authenticationFilter  = new JwtTokenAuthenticationFilter(failureHandler, tokenExtractor, matcher);
        
        authenticationFilter.setAllowSessionCreation(false);
		authenticationFilter.setApplicationEventPublisher(publisher);
		authenticationFilter.setAuthenticationDetailsSource(authenticationDetailsSource);
		authenticationFilter.setAuthenticationFailureHandler(failureHandler);
		authenticationFilter.setAuthenticationManager(authenticationManager);
		authenticationFilter.setAuthenticationSuccessHandler(successHandler);
		authenticationFilter.setContinueChainBeforeSuccessfulAuthentication(false);
		if (StringUtils.hasText(bizProperties.getLoginUrlPatterns())) {
			authenticationFilter.setFilterProcessesUrl(bizProperties.getLoginUrlPatterns());
		}
		// authenticationFilter.setMessageSource(messageSource);
		authenticationFilter.setRememberMeServices(rememberMeServices);
		authenticationFilter.setSessionAuthenticationStrategy(sessionStrategy);
        
        return authenticationFilter;
    }
     
	
	@Bean
	@ConditionalOnMissingBean
	public AbstractAuthenticationProcessingFilter authenticationFilter(AuthenticationFailureHandler failureHandler,
			AuthenticationManager authenticationManager, ApplicationEventPublisher publisher,
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource,
			AuthenticationSuccessHandler successHandler, RememberMeServices rememberMeServices,
			SessionAuthenticationStrategy sessionStrategy) {

		UsernamePasswordAuthenticationFilter authenticationFilter = new UsernamePasswordAuthenticationFilter();

		authenticationFilter.setAllowSessionCreation(bizProperties.isAllowSessionCreation());
		authenticationFilter.setApplicationEventPublisher(publisher);
		authenticationFilter.setAuthenticationDetailsSource(authenticationDetailsSource);
		authenticationFilter.setAuthenticationFailureHandler(failureHandler);
		authenticationFilter.setAuthenticationManager(authenticationManager);
		authenticationFilter.setAuthenticationSuccessHandler(successHandler);
		authenticationFilter.setContinueChainBeforeSuccessfulAuthentication(false);
		if (StringUtils.hasText(bizProperties.getLoginUrlPatterns())) {
			authenticationFilter.setFilterProcessesUrl(bizProperties.getLoginUrlPatterns());
		}
		// authenticationFilter.setMessageSource(messageSource);
		authenticationFilter.setPasswordParameter(bizProperties.getPasswordParameter());
		authenticationFilter.setPostOnly(bizProperties.isPostOnly());
		authenticationFilter.setRememberMeServices(rememberMeServices);
		authenticationFilter.setSessionAuthenticationStrategy(sessionStrategy);
		authenticationFilter.setUsernameParameter(bizProperties.getUsernameParameter());

		return authenticationFilter;
	}

	@Bean
	@ConditionalOnMissingBean
	public AuthenticationEntryPoint authenticationEntryPoint() {
		
		LoginUrlAuthenticationEntryPoint entryPoint = new LoginUrlAuthenticationEntryPoint(bizProperties.getLoginUrl());
		entryPoint.setForceHttps(bizProperties.isForceHttps());
		entryPoint.setUseForward(bizProperties.isUseForward());
		
		return entryPoint;
	}
	
	/**
	 * 系统登录注销过滤器；默认：org.springframework.security.web.authentication.logout.LogoutFilter
	 */
	@Bean
	@ConditionalOnMissingBean
	public LogoutFilter logoutFilter() {
		// 登录注销后的重定向地址：直接进入登录页面
		LogoutFilter logoutFilter = new LogoutFilter(bizProperties.getLoginUrl(), new SecurityContextLogoutHandler());
		logoutFilter.setFilterProcessesUrl(bizProperties.getLogoutUrlPatterns());
		return logoutFilter;
	}

	/*@Bean
	public FilterRegistrationBean<HttpParamsFilter> httpParamsFilter() {
		FilterRegistrationBean<HttpParamsFilter> filterRegistrationBean = new FilterRegistrationBean<HttpParamsFilter>();
		filterRegistrationBean.setFilter(new HttpParamsFilter());
		filterRegistrationBean.setOrder(-999);
		filterRegistrationBean.addUrlPatterns("/");
		return filterRegistrationBean;
	}*/


    
	@Autowired
	private UserDetailsService userDetailsService;
	@Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    
    @Autowired
    private AbstractAuthenticationProcessingFilter authenticationFilter;
    @Autowired
    private LogoutFilter logoutFilter;
    
    @Autowired
    private InvalidSessionStrategy invalidSessionStrategy;
    @Autowired
    private SessionInformationExpiredStrategy expiredSessionStrategy;
    
    @Autowired 
    private RestAuthenticationEntryPoint authenticationEntryPoint;
    @Autowired 
    private AuthenticationSuccessHandler successHandler;
    @Autowired 
    private AuthenticationFailureHandler failureHandler;
    @Autowired 
    private JwtRequestAuthenticationProvider ajaxAuthenticationProvider;
    @Autowired 
    private JwtAuthenticationProvider jwtAuthenticationProvider;
    @Autowired 
    private TokenExtractor tokenExtractor;
    @Autowired 
    private AuthenticationManager authenticationManager;
    @Autowired 
    private ObjectMapper objectMapper;
    
    @Autowired 
    private JwtAuthenticationProcessingFilter jwtAjaxLoginProcessingFilter;
    @Autowired 
    private JwtTokenAuthenticationFilter jwtTokenAuthenticationProcessingFilter;
    
	 
    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(jwtAuthenticationProvider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
    	http
        .csrf().disable() // We don't need CSRF for JWT based authentication
        .exceptionHandling()
        .authenticationEntryPoint(this.authenticationEntryPoint)
        
        .and()
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

        .and()
            .authorizeRequests()
                .antMatchers(bizProperties.getLoginUrlPatterns()).permitAll() // Login end-point
                .antMatchers(TOKEN_REFRESH_ENTRY_POINT).permitAll() // Token refresh end-point
                .antMatchers("/console").permitAll() // H2 Console Dash-board - only for testing
        .and()
            .authorizeRequests()
                .antMatchers(TOKEN_BASED_AUTH_ENTRY_POINT).authenticated() // Protected API End-points
        .and()
            .addFilterBefore(new CustomCorsFilter(), UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(jwtAjaxLoginProcessingFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(jwtTokenAuthenticationProcessingFilter, UsernamePasswordAuthenticationFilter.class);
    }
    
   /* @Override
    protected void configure(HttpSecurity http) throws Exception {
		
		HeadersConfigurer<HttpSecurity> headers = http.headers();
        
		if(null != bizProperties.getReferrerPolicy()) {
			headers.referrerPolicy(bizProperties.getReferrerPolicy()).and();
		}
        
		if(null != bizProperties.getFrameOptions()) {
			headers.frameOptions().disable();
		}
        
        
        http.csrf().disable();

        http.authorizeRequests()
                .requestMatchers(CorsUtils::isPreFlightRequest).permitAll()
                .antMatchers("/static/**").permitAll() 	// 不拦截静态资源
                .antMatchers("/api/**").permitAll()  	// 不拦截对外API
                    .anyRequest().authenticated();  	// 所有资源都需要登陆后才可以访问。

        http.logout().permitAll();  // 不拦截注销

        http.exceptionHandling().authenticationEntryPoint(authenticationEntryPoint);

        http.servletApi().disable();

        SessionManagementConfigurer<HttpSecurity> sessionManagement = http.sessionManagement();
        
        sessionManagement.enableSessionUrlRewriting(false)
        .invalidSessionStrategy(invalidSessionStrategy)
        .invalidSessionUrl(bizProperties.getRedirectUrl())
        .sessionAuthenticationErrorUrl(bizProperties.getFailureUrl())
        //.sessionAuthenticationStrategy(sessionAuthenticationStrategy)
        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);
        
        if(bizProperties.isMultipleSession()) {
        	sessionManagement.maximumSessions(bizProperties.getMaximumSessions()).expiredSessionStrategy(expiredSessionStrategy).expiredUrl(bizProperties.getExpiredUrl()).maxSessionsPreventsLogin(bizProperties.isMaxSessionsPreventsLogin());
        }
        
        http.addFilter(authenticationFilter)
                .addFilterBefore(logoutFilter, LogoutFilter.class);
        
        // 关闭csrf验证
        http.csrf().disable()
                // 对请求进行认证
                .authorizeRequests()
                // 所有 / 的所有请求 都放行
                .antMatchers("/").permitAll()
                // 所有 /login 的POST请求 都放行
                .antMatchers(HttpMethod.POST, "/login").permitAll()
                // 权限检查
                .antMatchers("/hello").hasAuthority("AUTH_WRITE")
                // 角色检查
                .antMatchers("/world").hasRole("ADMIN")
                // 所有请求需要身份认证
                .anyRequest().authenticated()
            .and()
                // 添加一个过滤器 所有访问 /login 的请求交给 JWTLoginFilter 来处理 这个类处理所有的JWT相关内容
                .addFilterBefore(new JWTLoginFilter("/login", authenticationManager()),
                        UsernamePasswordAuthenticationFilter.class)
                // 添加一个过滤器验证其他请求的Token是否合法
                .addFilterBefore(new JWTAuthenticationFilter(),
                        UsernamePasswordAuthenticationFilter.class);
        
        
        
        
        http.antMatcher("/**");
    }*/
    
    
	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.applicationContext = applicationContext;
	}

	public ApplicationContext getApplicationContext() {
		return applicationContext;
	}

}
