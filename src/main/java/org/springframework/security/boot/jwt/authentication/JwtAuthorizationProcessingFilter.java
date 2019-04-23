/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.jwt.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Jwt授权 (authorization)过滤器
 * 
 * @author ： <a href="https://github.com/vindell">vindell</a>
 */
public class JwtAuthorizationProcessingFilter extends AbstractAuthenticationProcessingFilter {

	private RequestMatcher loginAuthenticationRequestMatcher = new AntPathRequestMatcher("/login", "POST");

	public static final String AUTHORIZATION_PARAM = "token";
	/**
	 * HTTP Authorization header, equal to <code>Authorization</code>
	 */
	public static final String AUTHORIZATION_HEADER = "X-Authorization";

	private String authorizationHeaderName = AUTHORIZATION_HEADER;
	private String authorizationParamName = AUTHORIZATION_PARAM;
	private String authorizationCookieName = AUTHORIZATION_PARAM;

	public JwtAuthorizationProcessingFilter() {
		super(new AntPathRequestMatcher("/api/**"));
	}

	@Override
	protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
		// 登录获取JWT的请求不拦截
		return super.requiresAuthentication(request, response) && !loginAuthenticationRequestMatcher.matches(request);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {

		String token = obtainToken(request);

		if (token == null) {
			token = "";
		}

		token = token.trim();

		AbstractAuthenticationToken authRequest = new JwtAuthorizationToken(token);

		// Allow subclasses to set the "details" property
		setDetails(request, authRequest);

		return this.getAuthenticationManager().authenticate(authRequest);
	}

	protected void setDetails(HttpServletRequest request, AbstractAuthenticationToken authRequest) {
		authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
	}
	
	protected String obtainToken(HttpServletRequest request) {

		// 从header中获取token
		String token = request.getHeader(getAuthorizationHeaderName());
		// 如果header中不存在token，则从参数中获取token
		if (StringUtils.isEmpty(token)) {
			return request.getParameter(getAuthorizationParamName());
		}
		if (StringUtils.isEmpty(token)) {
			// 从 cookie 获取 token
			Cookie[] cookies = request.getCookies();
			if (null == cookies || cookies.length == 0) {
				return null;
			}
			for (Cookie cookie : cookies) {
				if (cookie.getName().equals(getAuthorizationCookieName())) {
					token = cookie.getValue();
					break;
				}
			}
		}
		return token;
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

}