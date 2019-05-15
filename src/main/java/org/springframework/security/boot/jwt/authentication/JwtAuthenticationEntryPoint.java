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
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.exception.AuthResponse;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.exception.AuthenticationCaptchaIncorrectException;
import org.springframework.security.boot.biz.exception.AuthenticationCaptchaNotFoundException;
import org.springframework.security.boot.biz.exception.AuthenticationMethodNotSupportedException;
import org.springframework.security.boot.biz.exception.AuthenticationTokenExpiredException;
import org.springframework.security.boot.biz.exception.AuthenticationTokenIncorrectException;
import org.springframework.security.boot.biz.exception.AuthenticationTokenNotFoundException;
import org.springframework.security.boot.jwt.exception.AuthenticationJwtExpiredException;
import org.springframework.security.boot.jwt.exception.AuthenticationJwtIncorrectException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.AuthenticationEntryPoint;

import com.alibaba.fastjson.JSONObject;

/**
 * Jwt认证 (authentication)处理端点
 * @author 		： <a href="https://github.com/vindell">wandl</a>
 */
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e)
			throws IOException, ServletException {
		writeJSONString(request, response, e);
	}
	
	protected void writeJSONString(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException e) throws IOException, ServletException{
		
		response.setStatus(HttpStatus.UNAUTHORIZED.value());
		response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
		
		if (e instanceof AuthenticationMethodNotSupportedException) {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHC_METHOD_NOT_ALLOWED.getCode(), e.getMessage()));
		} else if (e instanceof UsernameNotFoundException) {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHC_USER_NOT_FOUND.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHC_USER_NOT_FOUND.getMsgKey(), e.getMessage())));
		} else if (e instanceof BadCredentialsException) {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHC_CREDENTIALS_INCORRECT.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHC_CREDENTIALS_INCORRECT.getMsgKey(), e.getMessage())));
		} else if (e instanceof AuthenticationCaptchaNotFoundException) {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHC_CAPTCHA_REQUIRED.getCode(), e.getMessage()));
		} else if (e instanceof AuthenticationCaptchaIncorrectException) {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHC_CAPTCHA_INCORRECT.getCode(), e.getMessage()));
		} else if (e instanceof AuthenticationTokenNotFoundException) {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHZ_TOKEN_REQUIRED.getCode(), e.getMessage()));
		} else if (e instanceof AuthenticationTokenIncorrectException) {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHZ_TOKEN_INCORRECT.getCode(), e.getMessage()));
		} else if (e instanceof AuthenticationTokenExpiredException) {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHZ_TOKEN_EXPIRED.getCode(), e.getMessage()));
		} else if (e instanceof AuthenticationJwtIncorrectException) {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHZ_TOKEN_INCORRECT.getCode(), 
					messages.getMessage(AuthResponseCode.SC_AUTHZ_TOKEN_INCORRECT.getMsgKey(), e.getMessage())));
		} else if (e instanceof AuthenticationJwtExpiredException) {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHZ_TOKEN_EXPIRED.getCode(), 
					messages.getMessage(AuthResponseCode.SC_AUTHZ_TOKEN_EXPIRED.getMsgKey(), e.getMessage())));
		}  else if (e instanceof DisabledException) {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHC_USER_DISABLED.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHC_USER_DISABLED.getMsgKey(), e.getMessage())));
		}  else if (e instanceof LockedException) {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHC_USER_LOCKED.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHC_USER_LOCKED.getMsgKey(), e.getMessage())));	
		}  else if (e instanceof AccountExpiredException) {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHC_USER_EXPIRED.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHC_USER_EXPIRED.getMsgKey(), e.getMessage())));	
		}  else if (e instanceof CredentialsExpiredException) {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHC_CREDENTIALS_EXPIRED.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHC_CREDENTIALS_EXPIRED.getMsgKey(), e.getMessage())));	
		} else {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHC_FAIL.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHC_FAIL.getMsgKey())));
		}
	}

}
