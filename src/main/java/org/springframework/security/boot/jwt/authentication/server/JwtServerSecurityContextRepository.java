package org.springframework.security.boot.jwt.authentication.server;

import java.util.Objects;

import org.springframework.http.HttpCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationToken;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

/**
 * 1、ServerSecurityContextRepository 负责构造 SecurityContext 对象
 * https://www.jianshu.com/p/e013ca21d91d
 * https://www.baeldung.com/spring-oauth-login-webflux
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public class JwtServerSecurityContextRepository implements ServerSecurityContextRepository {
	
	/**
	 * HTTP Authorization Param, equal to <code>token</code>
	 */
	public static final String AUTHORIZATION_PARAM = "token";
	/**
	 * HTTP Authorization header, equal to <code>X-Authorization</code>
	 */
	public static final String AUTHORIZATION_HEADER = "X-Authorization";
	/**
	 * HTTP Authorization header, equal to <code>X-Uid</code>
	 */
	public static final String UID_HEADER = "X-Uid";
	/**
	 * HTTP Authorization header, equal to <code>X-Sign</code>
	 */
	public static final String SIGN_HEADER = "X-Sign";
	/**
	 * HTTP Authorization header, equal to <code>X-Longitude</code>
	 */
	public static final String LONGITUDE_HEADER = "X-Longitude";
	/**
	 * HTTP Authorization header, equal to <code>X-Latitude</code>
	 */
	public static final String LATITUDE_HEADER = "X-Latitude";

	private String authorizationHeaderName = AUTHORIZATION_HEADER;
	private String authorizationParamName = AUTHORIZATION_PARAM;
	private String authorizationCookieName = AUTHORIZATION_PARAM;
	private String uidHeaderName = UID_HEADER;
	private String signHeaderName = SIGN_HEADER;
	private String longitudeHeaderName = LONGITUDE_HEADER;
	private String latitudeHeaderName = LATITUDE_HEADER;

	private ReactiveAuthenticationManager authenticationManager;
	private ServerWebExchangeMatcher ignoreAuthenticationMatcher = ServerWebExchangeMatchers.anyExchange();

	public JwtServerSecurityContextRepository(ReactiveAuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	@Override
	public Mono<Void> save(ServerWebExchange serverWebExchange, SecurityContext securityContext) {
		return Mono.empty();
	}

	@Override
	public Mono<SecurityContext> load(ServerWebExchange serverWebExchange) {
		// 1、忽略不需要处理的请求
		if(this.ignoreAuthenticationMatcher.matches(serverWebExchange).block().isMatch()) {
			return Mono.empty();
		}
		// 2、从请求中提取token，并构造 SecurityContext
		ServerHttpRequest request = serverWebExchange.getRequest();
		return Mono.justOrEmpty(this.obtainToken(request)).map(token -> {
			if(!token.isEmpty()) {
				JwtAuthorizationToken authRequest = new JwtAuthorizationToken(this.obtainUid(request), token);
				authRequest.setLongitude(this.obtainLongitude(request));
				authRequest.setLatitude(this.obtainLatitude(request));
				authRequest.setSign(this.obtainSign(request));
				return authRequest;
			}
			return null;
		})
		.flatMap( authRequest -> this.authenticationManager.authenticate(authRequest).map(SecurityContextImpl::new));
		
	}
	
	protected String obtainUid(ServerHttpRequest request) {
		return request.getHeaders().getFirst(getUidHeaderName());
	}

	protected String obtainLongitude(ServerHttpRequest request) {
		return request.getHeaders().getFirst(getLongitudeHeaderName());
	}
	
	protected String obtainLatitude(ServerHttpRequest request) {
		return request.getHeaders().getFirst(getLatitudeHeaderName());
	}
	
	protected String obtainSign(ServerHttpRequest request) {
		return request.getHeaders().getFirst(getSignHeaderName());
	}
	
	protected String obtainToken(ServerHttpRequest request) {
		// 从header中获取token
		String token = request.getHeaders().getFirst(getAuthorizationHeaderName());
		// 如果header中不存在token，则从参数中获取token
		if (StringUtils.isEmpty(token)) {
			return request.getQueryParams().getFirst(getAuthorizationParamName());
		}
		if (StringUtils.isEmpty(token)) {
			// 从 cookie 获取 token
			MultiValueMap<String, HttpCookie> cookies = request.getCookies();
			if (null == cookies || cookies.size() == 0) {
				return null;
			}
			HttpCookie cookie = request.getCookies().getFirst(getAuthorizationCookieName());
			if(!Objects.isNull(cookie)) {
				token = cookie.getValue();
			}
		}
		if (token == null) {
			token = "";
		}
		return token.trim();
	}

	public String getAuthorizationHeaderName() {
		return authorizationHeaderName;
	}

	public void setAuthorizationHeaderName(String authorizationHeaderName) {
		this.authorizationHeaderName = authorizationHeaderName;
	}

	public String getAuthorizationParamName() {
		return authorizationParamName;
	}

	public void setAuthorizationParamName(String authorizationParamName) {
		this.authorizationParamName = authorizationParamName;
	}

	public String getAuthorizationCookieName() {
		return authorizationCookieName;
	}

	public void setAuthorizationCookieName(String authorizationCookieName) {
		this.authorizationCookieName = authorizationCookieName;
	}

	public String getUidHeaderName() {
		return uidHeaderName;
	}

	public void setUidHeaderName(String uidHeaderName) {
		this.uidHeaderName = uidHeaderName;
	}

	public String getSignHeaderName() {
		return signHeaderName;
	}

	public void setSignHeaderName(String signHeaderName) {
		this.signHeaderName = signHeaderName;
	}

	public String getLongitudeHeaderName() {
		return longitudeHeaderName;
	}

	public void setLongitudeHeaderName(String longitudeHeaderName) {
		this.longitudeHeaderName = longitudeHeaderName;
	}

	public String getLatitudeHeaderName() {
		return latitudeHeaderName;
	}

	public void setLatitudeHeaderName(String latitudeHeaderName) {
		this.latitudeHeaderName = latitudeHeaderName;
	}

	public ReactiveAuthenticationManager getAuthenticationManager() {
		return authenticationManager;
	}

	public void setAuthenticationManager(ReactiveAuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

}
