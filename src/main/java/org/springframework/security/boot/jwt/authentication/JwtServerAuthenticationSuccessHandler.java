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

import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.authentication.nested.MatchedServerAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.exception.AuthResponse;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.utils.SubjectUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.server.WebFilterExchange;

import com.alibaba.fastjson.JSONObject;

import reactor.core.publisher.Mono;

public class JwtServerAuthenticationSuccessHandler implements MatchedServerAuthenticationSuccessHandler {

	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	private JwtPayloadRepository payloadRepository;
	
	public JwtServerAuthenticationSuccessHandler(JwtPayloadRepository payloadRepository) {
		this.setPayloadRepository(payloadRepository);
	}
	
	@Override
	public boolean supports(Authentication authentication) {
		return SubjectUtils.isAssignableFrom(authentication.getClass(), JwtAuthenticationToken.class);
	}
	
	@Override
	public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {

    	UserDetails userDetails = (UserDetails) authentication.getPrincipal();
    	
    	String tokenString = "";
		// 账号首次登陆标记
    	if(SecurityPrincipal.class.isAssignableFrom(userDetails.getClass())) {
			// JSON Web Token (JWT)
			tokenString = getPayloadRepository().issueJwt((AbstractAuthenticationToken) authentication);
		} 

		ServerHttpResponse response = webFilterExchange.getExchange().getResponse();
		
    	// 设置状态码和响应头
		response.setStatusCode(HttpStatus.OK);
		response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
		
		// 国际化后的异常信息
		String message = messages.getMessage(AuthResponseCode.SC_AUTHC_SUCCESS.getMsgKey(), LocaleContextHolder.getLocale());
		// 写出JSON
		Map<String, Object> tokenMap = SubjectUtils.tokenMap(authentication, tokenString);
		String body = JSONObject.toJSONString(AuthResponse.success(message, tokenMap));
		DataBuffer buffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
        
	}
	

	public JwtPayloadRepository getPayloadRepository() {
		return payloadRepository;
	}

	public void setPayloadRepository(JwtPayloadRepository payloadRepository) {
		this.payloadRepository = payloadRepository;
	}
	
}
