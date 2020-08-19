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

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties.Jwt;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import reactor.core.publisher.Mono;

public class JwtReactiveAuthenticationManager implements ReactiveAuthenticationManager  {

	@Override
    public Mono<Authentication> authenticate(Authentication authentication) {
		
		/*
        String authToekn=authentication.getCredentials().toString();
        try {
            Claims claims= Jwt.parseJwt(authToekn);
            //todo 此处应该列出token中携带的角色表。
            List<String> roles=new ArrayList();
            roles.add("user");
            Authentication authentication1=new UsernamePasswordAuthenticationToken(
                    claims.getId(),
                    null,
                    roles.stream().map(role->new SimpleGrantedAuthority(role)).collect(Collectors.toList())
            );
            return Mono.just(authentication1);
        } catch (Exception e) {
           throw  new BadCredentialsException(e.getMessage());
        }*/
		return Mono.empty();
    }

}
