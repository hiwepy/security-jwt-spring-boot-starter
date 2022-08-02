package org.springframework.security.boot;

import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.biz.web.servlet.i18n.LocaleContextFilter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.biz.authentication.AuthenticatingFailureCounter;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationProcessingFilter;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationProvider;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationSuccessHandler;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.util.CollectionUtils;

@Configuration
@AutoConfigureBefore({ SecurityFilterAutoConfiguration.class })
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = SecurityJwtAuthzProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityBizProperties.class, SecurityJwtAuthcProperties.class, SecurityJwtAuthzProperties.class })
public class SecurityJwtAuthzFilterConfiguration {

	@Bean
	@ConditionalOnMissingBean
	public JwtAuthorizationProvider jwtAuthorizationProvider(JwtPayloadRepository payloadRepository, SecurityJwtAuthzProperties jwtAuthzProperties) {
		JwtAuthorizationProvider jwtAuthorizationProvider = new JwtAuthorizationProvider(payloadRepository);
		jwtAuthorizationProvider.setCheckExpiry(jwtAuthzProperties.isCheckExpiry());
		jwtAuthorizationProvider.setCheckPrincipal(jwtAuthzProperties.isCheckPrincipal());
		return jwtAuthorizationProvider;
	}


    @Configuration
    @ConditionalOnProperty(prefix = SecurityJwtAuthzProperties.PREFIX, value = "enabled", havingValue = "true")
	@EnableConfigurationProperties({ SecurityBizProperties.class, SecurityJwtAuthcProperties.class, SecurityJwtAuthzProperties.class })
    @Order(SecurityProperties.DEFAULT_FILTER_ORDER + 80)
	static class JwtAuthzWebSecurityConfigurerAdapter extends SecurityFilterChainConfigurer {

    	private final SecurityBizProperties bizProperties;
    	private final SecurityJwtAuthcProperties authcProperties;
    	private final SecurityJwtAuthzProperties authzProperties;

		private final AuthenticationEntryPoint authenticationEntryPoint;
		private final AuthenticationSuccessHandler authenticationSuccessHandler;
		private final AuthenticationFailureHandler authenticationFailureHandler;
		private final AuthenticationManager authenticationManager;
		private final LocaleContextFilter localeContextFilter;
		private final RememberMeServices rememberMeServices;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;

		public JwtAuthzWebSecurityConfigurerAdapter(

				SecurityBizProperties bizProperties,
   				SecurityJwtAuthcProperties authcProperties,
   				SecurityJwtAuthzProperties authzProperties,

				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
				ObjectProvider<AuthenticationListener> authenticationListenerProvider,
				ObjectProvider<MatchedAuthenticationEntryPoint> authenticationEntryPointProvider,
				ObjectProvider<MatchedAuthenticationFailureHandler> authenticationFailureHandlerProvider,
				ObjectProvider<LocaleContextFilter> localeContextProvider,
				ObjectProvider<RedirectStrategy> redirectStrategyProvider,
				ObjectProvider<RequestCache> requestCacheProvider,
				ObjectProvider<RememberMeServices> rememberMeServicesProvider,
				ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider

			) {

			super(bizProperties, redirectStrategyProvider.getIfAvailable(), requestCacheProvider.getIfAvailable());

			this.bizProperties = bizProperties;
   			this.authcProperties = authcProperties;
   			this.authzProperties = authzProperties;

			List<AuthenticationListener> authenticationListeners = authenticationListenerProvider.stream().collect(Collectors.toList());
			this.authenticationEntryPoint = super.authenticationEntryPoint(authcProperties.getPathPattern(), authenticationEntryPointProvider.stream().collect(Collectors.toList()));
			this.authenticationSuccessHandler = new JwtAuthorizationSuccessHandler();
			this.authenticationFailureHandler = super.authenticationFailureHandler(authenticationListeners, authenticationFailureHandlerProvider.stream().collect(Collectors.toList()));
			this.authenticationManager = authenticationManagerProvider.getIfAvailable();
			this.localeContextFilter = localeContextProvider.getIfAvailable();
			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();

		}

	    public JwtAuthorizationProcessingFilter authenticationProcessingFilter() throws Exception {

	    	JwtAuthorizationProcessingFilter authenticationFilter = new JwtAuthorizationProcessingFilter();

	    	/**
			 * 批量设置参数
			 */
			PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();

			map.from(bizProperties.getSession().isAllowSessionCreation()).to(authenticationFilter::setAllowSessionCreation);
			map.from(authenticationManager).to(authenticationFilter::setAuthenticationManager);
			map.from(authenticationSuccessHandler).to(authenticationFilter::setAuthenticationSuccessHandler);
			map.from(authenticationFailureHandler).to(authenticationFilter::setAuthenticationFailureHandler);
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
   			ignorePatterns.add(authcProperties.getPathPattern());
			authenticationFilter.setIgnoreRequestMatcher(ignorePatterns);

	        return authenticationFilter;
	    }

		@Bean
		public SecurityFilterChain jwtAuthzSecurityFilterChain(HttpSecurity http) throws Exception {
			// new DefaultSecurityFilterChain(new AntPathRequestMatcher(authcProperties.getPathPattern()), localeContextFilter, authenticationProcessingFilter());
			http.antMatcher(authcProperties.getPathPattern())
					// 异常处理
					.exceptionHandling((configurer) -> configurer.authenticationEntryPoint(authenticationEntryPoint))
					// 禁用 Http Basic
					.httpBasic((basic) -> basic.disable())
					// Filter 配置
					.addFilterBefore(localeContextFilter, UsernamePasswordAuthenticationFilter.class)
					.addFilterBefore(authenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class);

			return http.build();
		}

	}

}
