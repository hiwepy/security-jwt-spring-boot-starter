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

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.boot.biz.exception.AuthMethodNotSupportedException;
import org.springframework.security.boot.biz.exception.AuthTokenExpiredException;
import org.springframework.security.boot.biz.exception.AuthTokenIncorrectException;
import org.springframework.security.boot.biz.exception.ErrorCode;
import org.springframework.security.boot.biz.exception.ErrorResponse;
import org.springframework.security.boot.biz.exception.IdentityCodeExpiredException;
import org.springframework.security.boot.biz.exception.IdentityCodeIncorrectException;
import org.springframework.security.boot.jwt.exception.JwtExpiredException;
import org.springframework.security.boot.jwt.exception.JwtIncorrectException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import com.alibaba.fastjson.JSONObject;

public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e)
			throws IOException, ServletException {
			
		response.setStatus(HttpStatus.UNAUTHORIZED.value());
		response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
		
		if (e instanceof BadCredentialsException) {
			JSONObject.writeJSONString(response.getWriter(), ErrorResponse.of("Invalid username or password", ErrorCode.AUTHENTICATION, HttpStatus.UNAUTHORIZED));
		} else if (e instanceof IdentityCodeIncorrectException) {
			JSONObject.writeJSONString(response.getWriter(), ErrorResponse.of("Code was incorrect", ErrorCode.IDENTITY, HttpStatus.UNAUTHORIZED));
		} else if (e instanceof IdentityCodeExpiredException) {
			JSONObject.writeJSONString(response.getWriter(), ErrorResponse.of("Code has expired", ErrorCode.IDENTITY, HttpStatus.UNAUTHORIZED));
		} else if (e instanceof AuthTokenIncorrectException) {
			JSONObject.writeJSONString(response.getWriter(), ErrorResponse.of("Token was incorrect", ErrorCode.TOKEN, HttpStatus.UNAUTHORIZED));
		} else if (e instanceof AuthTokenExpiredException) {
			JSONObject.writeJSONString(response.getWriter(), ErrorResponse.of("Token has expired", ErrorCode.TOKEN, HttpStatus.UNAUTHORIZED));
		} else if (e instanceof JwtIncorrectException) {
			JSONObject.writeJSONString(response.getWriter(), ErrorResponse.of("JWT was incorrect", ErrorCode.TOKEN, HttpStatus.UNAUTHORIZED));
		} else if (e instanceof JwtExpiredException) {
			JSONObject.writeJSONString(response.getWriter(), ErrorResponse.of("JWT has expired", ErrorCode.TOKEN, HttpStatus.UNAUTHORIZED));
		} else if (e instanceof AuthMethodNotSupportedException) {
		    JSONObject.writeJSONString(response.getWriter(), ErrorResponse.of(e.getMessage(), ErrorCode.AUTHENTICATION, HttpStatus.UNAUTHORIZED));
		} else {
			JSONObject.writeJSONString(response.getWriter(), ErrorResponse.of("Authentication failed", ErrorCode.AUTHENTICATION, HttpStatus.UNAUTHORIZED));
		}

	}

}