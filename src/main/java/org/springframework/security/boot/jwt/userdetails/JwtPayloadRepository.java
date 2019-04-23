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

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.springframework.security.boot.jwt.authentication.JwtAuthorizationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;

import com.github.vindell.jwt.JwtPayload;

/**
 * Abstract JSON Web Token (JWT) Payload Repository
 * @author ： <a href="https://github.com/vindell">vindell</a>
 */
public abstract class JwtPayloadRepository {

	public abstract String issueJwt(JwtAuthorizationToken token, SecurityContext context, ServletRequest request,
			ServletResponse response);

	public abstract boolean verify(JwtAuthorizationToken token, SecurityContext context, ServletRequest request,
			ServletResponse response, boolean checkExpiry) throws AuthenticationException;

	public abstract JwtPayload getPayload(JwtAuthorizationToken token, boolean checkExpiry);

}
