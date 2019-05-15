package org.springframework.security.boot.jwt.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.exception.AuthResponse;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.jwt.exception.AuthenticationJwtExpiredException;
import org.springframework.security.boot.jwt.exception.AuthenticationJwtIncorrectException;
import org.springframework.security.boot.jwt.exception.AuthenticationJwtInvalidException;
import org.springframework.security.boot.utils.SubjectUtils;
import org.springframework.security.core.AuthenticationException;

import com.alibaba.fastjson.JSONObject;

/**
 * Jwt认证、授权 (authorization) 失败处理器
 * @author ： <a href="https://github.com/vindell">vindell</a>
 */
public class JwtMatchedAuthcOrAuthzFailureHandler implements MatchedAuthenticationFailureHandler {
	
	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	
	@Override
	public boolean supports(AuthenticationException e) {
		return SubjectUtils.supports(e.getClass(), AuthenticationJwtIncorrectException.class,
				AuthenticationJwtInvalidException.class, AuthenticationJwtExpiredException.class);
	}
	
	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException e) throws IOException, ServletException {
		
		response.setStatus(HttpStatus.UNAUTHORIZED.value());
		response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
		
			
		if (e instanceof AuthenticationJwtIncorrectException) {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHZ_TOKEN_INCORRECT.getCode(), 
					messages.getMessage(AuthResponseCode.SC_AUTHZ_TOKEN_INCORRECT.getMsgKey(), e.getMessage())));
		} else if (e instanceof AuthenticationJwtExpiredException) {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHZ_TOKEN_EXPIRED.getCode(), 
					messages.getMessage(AuthResponseCode.SC_AUTHZ_TOKEN_EXPIRED.getMsgKey(), e.getMessage())));
		}  
		
		else {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHC_FAIL.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHC_FAIL.getMsgKey())));
		}
		 
		
	}
	
}
