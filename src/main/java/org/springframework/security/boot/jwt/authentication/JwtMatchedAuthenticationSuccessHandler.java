package org.springframework.security.boot.jwt.authentication;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.utils.SubjectUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import com.alibaba.fastjson.JSONObject;

/**
 * Jwt认证 (authentication)成功回调器：讲认证信息写回前端
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public class JwtMatchedAuthenticationSuccessHandler implements MatchedAuthenticationSuccessHandler {
   
	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	private JwtPayloadRepository payloadRepository;
	private final String EMPTY = "null";
	
	public JwtMatchedAuthenticationSuccessHandler(JwtPayloadRepository payloadRepository) {
		this.setPayloadRepository(payloadRepository);
	}
	
	@Override
	public boolean supports(Authentication authentication) {
		return SubjectUtils.isAssignableFrom(authentication.getClass(), JwtAuthenticationToken.class);
	}

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        
    	UserDetails userDetails = (UserDetails) authentication.getPrincipal();
    	
		Map<String, Object> tokenMap = new HashMap<String, Object>();
		tokenMap.put("code", AuthResponseCode.SC_AUTHC_SUCCESS.getCode());
		tokenMap.put("msg", messages.getMessage(AuthResponseCode.SC_AUTHC_SUCCESS.getMsgKey()));
		
		// 账号首次登陆标记
		if(SecurityPrincipal.class.isAssignableFrom(userDetails.getClass())) {
			SecurityPrincipal securityPrincipal = (SecurityPrincipal) userDetails;
			tokenMap.put("initial", securityPrincipal.isInitial());
			tokenMap.put("alias", StringUtils.hasText(securityPrincipal.getAlias()) ? securityPrincipal.getAlias() : EMPTY);
			tokenMap.put("usercode", StringUtils.hasText(securityPrincipal.getUsercode()) ? securityPrincipal.getUsercode() : EMPTY);
			tokenMap.put("userkey", StringUtils.hasText(securityPrincipal.getUserkey()) ? securityPrincipal.getUserkey() : EMPTY);
			tokenMap.put("userid", StringUtils.hasText(securityPrincipal.getUserid()) ? securityPrincipal.getUserid() : EMPTY);
			tokenMap.put("roleid", StringUtils.hasText(securityPrincipal.getRoleid()) ? securityPrincipal.getRoleid() : EMPTY );
			tokenMap.put("role", StringUtils.hasText(securityPrincipal.getRole()) ? securityPrincipal.getRole() : EMPTY);
			tokenMap.put("roles", CollectionUtils.isEmpty(securityPrincipal.getRoles()) ? new ArrayList<>() : securityPrincipal.getRoles() );
			tokenMap.put("restricted", securityPrincipal.isRestricted());
			tokenMap.put("profile", CollectionUtils.isEmpty(securityPrincipal.getProfile()) ? new HashMap<>() : securityPrincipal.getProfile() );
			tokenMap.put("faced", securityPrincipal.isFace());
			tokenMap.put("faceId", StringUtils.hasText(securityPrincipal.getFaceId()) ? securityPrincipal.getFaceId() : EMPTY ); 
		} else {
			tokenMap.put("initial", false);
			tokenMap.put("alias", "匿名账户");
			tokenMap.put("usercode", EMPTY);
			tokenMap.put("userkey", EMPTY);
			tokenMap.put("userid", EMPTY);
			tokenMap.put("roleid", EMPTY);
			tokenMap.put("role", EMPTY);
			tokenMap.put("roles", new ArrayList<>());
			tokenMap.put("restricted", false);
			tokenMap.put("profile", new HashMap<>());
			tokenMap.put("faced", false);
			tokenMap.put("faceId", EMPTY);
		}
		tokenMap.put("perms", userDetails.getAuthorities());
		tokenMap.put("token", getPayloadRepository().issueJwt((AbstractAuthenticationToken) authentication));
		tokenMap.put("username", userDetails.getUsername());
		
		response.setStatus(HttpStatus.OK.value());
		response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
		
		JSONObject.writeJSONString(response.getWriter(), tokenMap);
    	 
    }
    
	public JwtPayloadRepository getPayloadRepository() {
		return payloadRepository;
	}

	public void setPayloadRepository(JwtPayloadRepository payloadRepository) {
		this.payloadRepository = payloadRepository;
	}

}
