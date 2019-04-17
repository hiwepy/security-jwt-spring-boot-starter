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
package org.springframework.security.boot.jwt.userdetails;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

/**
 * JWT保存的用户信息
 * @author 		： <a href="https://github.com/vindell">wandl</a>
 */
@SuppressWarnings("serial")
public class JWTUserDetails extends User {

	private final Long userId;
	private final String secret;

	public JWTUserDetails(long userId, String username, String password,
			Collection<? extends GrantedAuthority> authorities, String secret) {
		this(userId, username, password, true, true, true, true, authorities, secret);
	}

	public JWTUserDetails(long userId, String username, String password, boolean enabled, boolean accountNonExpired,
			boolean credentialsNonExpired, boolean accountNonLocked,
			Collection<? extends GrantedAuthority> authorities, String secret) {
		super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
		if (username != null && !"".equals(username) && password != null) {
			this.userId = userId;
			this.secret = secret;
		} else {
			throw new IllegalArgumentException("Cannot pass null or empty values to constructor");
		}
	}

	public Long getUserId() {
		return userId;
	}

	public String getSecret() {
		return secret;
	}
	
}
