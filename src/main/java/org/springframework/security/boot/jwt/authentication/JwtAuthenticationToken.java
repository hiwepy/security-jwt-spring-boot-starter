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

import java.util.Collection;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

/**
 * Jwt认证 (authentication) Token
 * @author ： <a href="https://github.com/vindell">vindell</a>
 */
@SuppressWarnings("serial")
public class JwtAuthenticationToken extends UsernamePasswordAuthenticationToken {

	/**
	 * This constructor can be safely used by any code that wishes to create a
	 * <code>JwtAuthenticationToken</code>, as the {@link #isAuthenticated()}
	 * will return <code>false</code>.
	 * @param principal The principal
	 * @param credentials The credentials
	 * 
	 */
	public JwtAuthenticationToken(Object principal, Object credentials) {
		super(principal, credentials);
	}
	
	/**
	 * This constructor should only be used by <code>AuthenticationManager</code> or
	 * <code>AuthenticationProvider</code> implementations that are satisfied with
	 * producing a trusted (i.e. {@link #isAuthenticated()} = <code>true</code>)
	 * authentication token.
	 *
	 * @param principal The principal
	 * @param credentials The credentials
	 * @param authorities The authorities
	 */
	public JwtAuthenticationToken(Object principal, Object credentials,
			Collection<? extends GrantedAuthority> authorities) {
		super(principal, credentials, authorities);
	}

}