package org.springframework.security.boot.jwt.authentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationProcessingFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Jwt认证 (authentication)过滤器
 * @author ： <a href="https://github.com/vindell">vindell</a>
 */
public class JwtAuthenticationProcessingFilter extends PostRequestAuthenticationProcessingFilter {

	public JwtAuthenticationProcessingFilter(ObjectMapper objectMapper) {
		super(objectMapper);
	}
	
	@Override
	protected AbstractAuthenticationToken authenticationToken(String username, String password) {
		return new JwtAuthenticationToken( username, password);
	}
	
}
