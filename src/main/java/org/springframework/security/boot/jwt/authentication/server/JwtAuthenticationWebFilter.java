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
package org.springframework.security.boot.jwt.authentication.server;

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;

import reactor.core.publisher.Mono;

public class JwtAuthenticationWebFilter extends AuthenticationWebFilter {
	
	private ServerAuthenticationFailureHandler authenticationFailureHandler;
	private ServerWebExchangeMatcher ignoreAuthenticationMatcher = ServerWebExchangeMatchers.anyExchange();

	public JwtAuthenticationWebFilter(ReactiveAuthenticationManager authenticationManager) {
		super(authenticationManager);
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		if(this.ignoreAuthenticationMatcher.matches(exchange).block().isMatch()) {
			return chain.filter(exchange);
		}
		WebFilterExchange webFilterExchange = new WebFilterExchange(exchange, chain);
		return super.filter(exchange, chain)
				.onErrorResume(AuthenticationException.class, e -> this.authenticationFailureHandler
						.onAuthenticationFailure(webFilterExchange, e));
	}

	@Override
	public void setAuthenticationFailureHandler(ServerAuthenticationFailureHandler authenticationFailureHandler) {
		super.setAuthenticationFailureHandler(authenticationFailureHandler);
		this.authenticationFailureHandler = authenticationFailureHandler;
	}

	public void setIgnoreAuthenticationMatcher(ServerWebExchangeMatcher ignoreAuthenticationMatcher) {
		this.ignoreAuthenticationMatcher = ignoreAuthenticationMatcher;
	}

	public ServerWebExchangeMatcher getIgnoreAuthenticationMatcher() {
		return ignoreAuthenticationMatcher;
	}

	public ServerAuthenticationFailureHandler getAuthenticationFailureHandler() {
		return authenticationFailureHandler;
	}
	
	
	
}