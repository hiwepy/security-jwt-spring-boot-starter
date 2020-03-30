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
package org.springframework.security.boot.jwt.utils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.utils.SubjectUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.CollectionUtils;

/**
 * TODO
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
public class SubjectJwtUtils extends SubjectUtils {

	private static MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	private static final String EMPTY = "null";
	
	public static Map<String, Object> tokenMap(Authentication authentication, String token){
		
		UserDetails userDetails = (UserDetails) authentication.getPrincipal();
		
		Map<String, Object> tokenMap = new HashMap<String, Object>();
		
		tokenMap.put("code", AuthResponseCode.SC_AUTHC_SUCCESS.getCode());
		tokenMap.put("msg", messages.getMessage(AuthResponseCode.SC_AUTHC_SUCCESS.getMsgKey()));
		tokenMap.put("status", "success");
		
		// 账号首次登陆标记
		if(SecurityPrincipal.class.isAssignableFrom(userDetails.getClass())) {
			SecurityPrincipal securityPrincipal = (SecurityPrincipal) userDetails;
			tokenMap.put("initial", securityPrincipal.isInitial());
			tokenMap.put("alias", StringUtils.defaultString(securityPrincipal.getAlias(), EMPTY));
			tokenMap.put("userid", StringUtils.defaultString(securityPrincipal.getUserid(), EMPTY));
			tokenMap.put("userkey", StringUtils.defaultString(securityPrincipal.getUserkey(), EMPTY));
			tokenMap.put("usercode", StringUtils.defaultString(securityPrincipal.getUsercode(), EMPTY));
			tokenMap.put("username", userDetails.getUsername());
			tokenMap.put("perms", userDetails.getAuthorities());
			tokenMap.put("roleid", StringUtils.defaultString(securityPrincipal.getRoleid(), EMPTY ));
			tokenMap.put("role", StringUtils.defaultString(securityPrincipal.getRole(), EMPTY));
			tokenMap.put("roles", CollectionUtils.isEmpty(securityPrincipal.getRoles()) ? new ArrayList<>() : securityPrincipal.getRoles() );
			tokenMap.put("restricted", securityPrincipal.isRestricted());
			tokenMap.put("profile", CollectionUtils.isEmpty(securityPrincipal.getProfile()) ? new HashMap<>() : securityPrincipal.getProfile() );
			tokenMap.put("faced", securityPrincipal.isFace());
			tokenMap.put("faceId", StringUtils.defaultString(securityPrincipal.getFaceId(), EMPTY ));
			// JSON Web Token (JWT)
			tokenMap.put("token", token);
		} else {
			tokenMap.put("initial", false);
			tokenMap.put("alias", "匿名账户");
			tokenMap.put("userid", EMPTY);
			tokenMap.put("userkey", EMPTY);
			tokenMap.put("usercode", EMPTY);
			tokenMap.put("username", EMPTY);
			tokenMap.put("perms", new ArrayList<>());
			tokenMap.put("roleid", EMPTY);
			tokenMap.put("role", EMPTY);
			tokenMap.put("roles", new ArrayList<>());
			tokenMap.put("restricted", false);
			tokenMap.put("profile", new HashMap<>());
			tokenMap.put("faced", false);
			tokenMap.put("faceId", EMPTY);
			tokenMap.put("token", EMPTY);
		}
		
		return tokenMap;
		
	}
	
}
