package org.springframework.security.boot.jwt.authentication;

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.exception.AuthMethodNotSupportedException;
import org.springframework.security.boot.biz.exception.PostLoginResponse;
import org.springframework.security.boot.jwt.exception.ErrorCode;
import org.springframework.security.boot.jwt.exception.ErrorResponse;
import org.springframework.security.boot.jwt.exception.JwtExpiredTokenException;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import com.alibaba.fastjson.JSONObject;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * 
 * @author vladimir.stankovic
 *
 * Aug 3, 2016
 */
public class JwtRequestAuthenticationFailureHandler extends PostRequestAuthenticationFailureHandler {
   
	public JwtRequestAuthenticationFailureHandler(String defaultFailureUrl) {
		super(defaultFailureUrl);
	}
	
	public JwtRequestAuthenticationFailureHandler(List<AuthenticationListener> authenticationListeners, String defaultFailureUrl) {
		super(authenticationListeners, defaultFailureUrl);
	}
	
	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException e) throws IOException, ServletException {
		
		//调用事件监听器
		if(getAuthenticationListeners() != null && getAuthenticationListeners().size() > 0){
			for (AuthenticationListener authenticationListener : getAuthenticationListeners()) {
				authenticationListener.onFailure(request, response, e);
			}
		}
		
		
		/*
		 * if Rest request return 401 Unauthorized else rediect to specific page
		 */
		if (WebUtils.isPostRequest(request)) {

			response.setStatus(HttpStatus.UNAUTHORIZED.value());
			response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);

			if (e instanceof BadCredentialsException) {
				JSONObject.writeJSONString(response.getWriter(), PostLoginResponse.of("Invalid username or password", HttpStatus.UNAUTHORIZED));
			} else if (e instanceof JwtExpiredTokenException) {
				JSONObject.writeJSONString(response.getWriter(), PostLoginResponse.of("Token has expired", HttpStatus.UNAUTHORIZED));
			} else if (e instanceof AuthMethodNotSupportedException) {
				JSONObject.writeJSONString(response.getWriter(), PostLoginResponse.of(e.getMessage(), HttpStatus.UNAUTHORIZED));
			} else {
				JSONObject.writeJSONString(response.getWriter(), PostLoginResponse.of("Authentication failed", HttpStatus.UNAUTHORIZED));
			}
		} else {
			super.onAuthenticationFailure(request, response, e);
		}

		
		response.setStatus(HttpStatus.UNAUTHORIZED.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		
		if (e instanceof BadCredentialsException) {
			mapper.writeValue(response.getWriter(), ErrorResponse.of("Invalid username or password", ErrorCode.AUTHENTICATION, HttpStatus.UNAUTHORIZED));
		} else if (e instanceof JwtExpiredTokenException) {
			mapper.writeValue(response.getWriter(), ErrorResponse.of("Token has expired", ErrorCode.JWT_TOKEN_EXPIRED, HttpStatus.UNAUTHORIZED));
		} else if (e instanceof AuthMethodNotSupportedException) {
		    mapper.writeValue(response.getWriter(), ErrorResponse.of(e.getMessage(), ErrorCode.AUTHENTICATION, HttpStatus.UNAUTHORIZED));
		}

		mapper.writeValue(response.getWriter(), ErrorResponse.of("Authentication failed", ErrorCode.AUTHENTICATION, HttpStatus.UNAUTHORIZED));
	}
}
