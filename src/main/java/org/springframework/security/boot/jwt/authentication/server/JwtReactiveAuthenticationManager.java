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

import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationToken;
import org.springframework.security.boot.jwt.exception.AuthenticationJwtExpiredException;
import org.springframework.security.boot.jwt.exception.AuthenticationJwtNotFoundException;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.util.Assert;

import com.github.hiwepy.jwt.JwtPayload;

import reactor.core.publisher.Mono;

/**
 * 3、JWT Authentication Manager For Reactive （负责校验 Authentication 对象）
 */
public class JwtReactiveAuthenticationManager implements ReactiveAuthenticationManager  {

	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
	private final Logger logger = LoggerFactory.getLogger(getClass());
	private final JwtPayloadRepository payloadRepository;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
    private boolean checkExpiry = false;
    
    public JwtReactiveAuthenticationManager(final JwtPayloadRepository payloadRepository) {
        this.payloadRepository = payloadRepository;
    }
    
	@Override
    public Mono<Authentication> authenticate(Authentication authentication) {
		
		Assert.notNull(authentication, "No authentication data provided");
    	
    	if (logger.isDebugEnabled()) {
			logger.debug("Processing authentication request : " + authentication);
		}
    	
    	String uid = (String) authentication.getPrincipal();
        String token = (String) authentication.getCredentials();

		if (!StringUtils.hasText(token)) {
			logger.debug("No JWT found in request.");
			throw new AuthenticationJwtNotFoundException("No JWT found in request.");
		}
		
		JwtAuthorizationToken jwtToken = (JwtAuthorizationToken) authentication;
		
		// 检查token有效性
		if(isCheckExpiry() && !getPayloadRepository().verify(jwtToken, isCheckExpiry())) {
			throw new AuthenticationJwtExpiredException("Token Expired");
		}
		
		// 解析Token载体信息
		JwtPayload payload = getPayloadRepository().getPayload(jwtToken, checkExpiry);
		
		Set<GrantedAuthority> grantedAuthorities = new HashSet<GrantedAuthority>();
		
		// 角色必须是ROLE_开头，可以在数据库中设置
        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_"+ payload.getRole());
        grantedAuthorities.add(grantedAuthority);
   		
   		// 用户权限标记集合
   		Set<String> perms = payload.getPerms();
		for (String perm : perms ) {
			GrantedAuthority authority = new SimpleGrantedAuthority(perm);
            grantedAuthorities.add(authority);
		}
		
		Map<String, Object> claims = payload.getClaims();
		
		uid = Objects.isNull(uid) ? payload.getClientId() : uid;
		
		SecurityPrincipal principal = new SecurityPrincipal(uid, payload.getTokenId(), payload.isEnabled(),
				payload.isAccountNonExpired(), payload.isCredentialsNonExpired(), payload.isAccountNonLocked(),
				grantedAuthorities);
	
		principal.setUid(String.valueOf(claims.get("userid")));
		principal.setUkey(String.valueOf(claims.get("userkey")));
		principal.setUcode(String.valueOf(claims.get("usercode")));
		principal.setPerms(new HashSet<String>(perms));
		principal.setRid(payload.getRoleid());
		principal.setRkey(payload.getRole());
		principal.setRoles(payload.getRoles());
		principal.setInitial(payload.isInitial());
		principal.setProfile(payload.getProfile());
		
        // User Status Check
        getUserDetailsChecker().check(principal);
        
        JwtAuthorizationToken authenticationToken = new JwtAuthorizationToken(principal, payload, principal.getAuthorities());        	
        authenticationToken.setDetails(authentication.getDetails());
        
        return Mono.justOrEmpty(authenticationToken);
    }
	
	public void setUserDetailsChecker(UserDetailsChecker userDetailsChecker) {
		this.userDetailsChecker = userDetailsChecker;
	}

	public UserDetailsChecker getUserDetailsChecker() {
		return userDetailsChecker;
	}

	public JwtPayloadRepository getPayloadRepository() {
		return payloadRepository;
	}

	public boolean isCheckExpiry() {
		return checkExpiry;
	}

	public void setCheckExpiry(boolean checkExpiry) {
		this.checkExpiry = checkExpiry;
	}
}
