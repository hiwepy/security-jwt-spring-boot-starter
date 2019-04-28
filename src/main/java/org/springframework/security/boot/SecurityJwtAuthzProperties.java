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
package org.springframework.security.boot;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationProcessingFilter;
import org.springframework.security.core.Authentication;

@ConfigurationProperties(prefix = SecurityJwtAuthzProperties.PREFIX)
public class SecurityJwtAuthzProperties {

	public static final String PREFIX = "spring.security.jwt.authz";
	
	/** Whether Enable JWT Authorization. */
	private boolean enabled = false;
	private boolean allowSessionCreation = false;
	/** Authorization Path Pattern */
	private String pathPattern = "/**";
	private String[] ignorePatterns = new String[] {"/login/jwt"};
	
	/**
	 * Specifies the name of the header on where to find the token (i.e.
	 * X-Authorization).
	 */
	private String authorizationHeaderName = JwtAuthorizationProcessingFilter.AUTHORIZATION_HEADER;
	private String authorizationParamName = JwtAuthorizationProcessingFilter.AUTHORIZATION_PARAM;
	private String authorizationCookieName = JwtAuthorizationProcessingFilter.AUTHORIZATION_PARAM;
	/**
	 * Indicates if the filter chain should be continued prior to delegation to
	 * {@link #successfulAuthentication(HttpServletRequest, HttpServletResponse, FilterChain, Authentication)}
	 * , which may be useful in certain environment (such as Tapestry applications).
	 * Defaults to <code>false</code>.
	 */
	private boolean continueChainBeforeSuccessfulAuthentication = true;

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}
	
	public boolean isAllowSessionCreation() {
		return allowSessionCreation;
	}

	public void setAllowSessionCreation(boolean allowSessionCreation) {
		this.allowSessionCreation = allowSessionCreation;
	}

	public String getPathPattern() {
		return pathPattern;
	}

	public void setPathPattern(String pathPattern) {
		this.pathPattern = pathPattern;
	}
	
	public String[] getIgnorePatterns() {
		return ignorePatterns;
	}

	public void setIgnorePatterns(String[] ignorePatterns) {
		this.ignorePatterns = ignorePatterns;
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

	public boolean isContinueChainBeforeSuccessfulAuthentication() {
		return continueChainBeforeSuccessfulAuthentication;
	}

	public void setContinueChainBeforeSuccessfulAuthentication(boolean continueChainBeforeSuccessfulAuthentication) {
		this.continueChainBeforeSuccessfulAuthentication = continueChainBeforeSuccessfulAuthentication;
	}

}
