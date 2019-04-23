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
import org.springframework.security.boot.biz.exception.ErrorCode;
import org.springframework.security.boot.biz.exception.ErrorResponse;
import org.springframework.security.boot.jwt.exception.JwtExpiredException;
import org.springframework.security.boot.jwt.exception.JwtIncorrectException;
import org.springframework.security.core.AuthenticationException;

import com.alibaba.fastjson.JSONObject;

/**
 * Jwt授权 (authorization) 失败处理器
 * @author ： <a href="https://github.com/vindell">vindell</a>
 */
public class JwtAuthorizationFailureHandler extends PostRequestAuthenticationFailureHandler {

	public JwtAuthorizationFailureHandler(String defaultFailureUrl) {
		super(defaultFailureUrl);
	}
	
	public JwtAuthorizationFailureHandler(List<AuthenticationListener> authenticationListeners, String defaultFailureUrl) {
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
		
		response.setStatus(HttpStatus.UNAUTHORIZED.value());
		response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);

		if (e instanceof BadCredentialsException) {
			JSONObject.writeJSONString(response.getWriter(), ErrorResponse.of("Invalid username or password", ErrorCode.AUTHENTICATION, HttpStatus.UNAUTHORIZED));
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
