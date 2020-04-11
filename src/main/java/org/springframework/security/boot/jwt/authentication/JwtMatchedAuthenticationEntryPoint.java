/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
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
import java.nio.charset.StandardCharsets;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.exception.AuthResponse;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.jwt.exception.AuthenticationJwtExpiredException;
import org.springframework.security.boot.jwt.exception.AuthenticationJwtIncorrectException;
import org.springframework.security.boot.jwt.exception.AuthenticationJwtInvalidException;
import org.springframework.security.boot.jwt.exception.AuthenticationJwtIssuedException;
import org.springframework.security.boot.jwt.exception.AuthenticationJwtNotFoundException;
import org.springframework.security.boot.utils.SubjectUtils;
import org.springframework.security.core.AuthenticationException;

import com.alibaba.fastjson.JSONObject;

/**
 * Jwt认证 (authentication)处理端点
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
public class JwtMatchedAuthenticationEntryPoint implements MatchedAuthenticationEntryPoint {

	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	protected Logger logger = LoggerFactory.getLogger(getClass());
	
	@Override
	public boolean supports(AuthenticationException e) {
		return SubjectUtils.isAssignableFrom(e.getClass(), AuthenticationJwtIssuedException.class,
				AuthenticationJwtNotFoundException.class, AuthenticationJwtExpiredException.class,
				AuthenticationJwtInvalidException.class, AuthenticationJwtIncorrectException.class);
	}
	
	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e)
			throws IOException, ServletException {
		
		logger.debug("Locale : {}" , LocaleContextHolder.getLocale());
		
		response.setStatus(HttpStatus.UNAUTHORIZED.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding(StandardCharsets.UTF_8.name());
		
		if (e instanceof AuthenticationJwtNotFoundException) {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHZ_TOKEN_REQUIRED.getCode(), 
					messages.getMessage(AuthResponseCode.SC_AUTHZ_TOKEN_REQUIRED.getMsgKey(), e.getMessage())));
		} else if (e instanceof AuthenticationJwtIssuedException) {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHZ_TOKEN_ISSUED.getCode(), 
					messages.getMessage(AuthResponseCode.SC_AUTHZ_TOKEN_ISSUED.getMsgKey(), e.getMessage())));
		} else if (e instanceof AuthenticationJwtExpiredException) {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHZ_TOKEN_EXPIRED.getCode(), 
					messages.getMessage(AuthResponseCode.SC_AUTHZ_TOKEN_EXPIRED.getMsgKey(), e.getMessage())));
		} else if (e instanceof AuthenticationJwtInvalidException) {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHZ_TOKEN_INVALID.getCode(), 
					messages.getMessage(AuthResponseCode.SC_AUTHZ_TOKEN_INVALID.getMsgKey(), e.getMessage())));
		} else if (e instanceof AuthenticationJwtIncorrectException) {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHZ_TOKEN_INCORRECT.getCode(), 
					messages.getMessage(AuthResponseCode.SC_AUTHZ_TOKEN_INCORRECT.getMsgKey(), e.getMessage())));
		}  
		else {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHZ_FAIL.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHZ_FAIL.getMsgKey())));
		}
	}

}
