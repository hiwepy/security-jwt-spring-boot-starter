package org.springframework.security.boot.jwt.authentication;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.utils.SubjectUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

import com.alibaba.fastjson.JSONObject;

/**
 * Jwt认证 (authentication)成功回调器：讲认证信息写回前端
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public class JwtMatchedAuthenticationSuccessHandler implements MatchedAuthenticationSuccessHandler {
   
	private JwtPayloadRepository payloadRepository;
	
	public JwtMatchedAuthenticationSuccessHandler(JwtPayloadRepository payloadRepository) {
		this.setPayloadRepository(payloadRepository);
	}
	
	@Override
	public boolean supports(Authentication authentication) {
		return SubjectUtils.supports(authentication.getClass(), JwtAuthenticationToken.class);
	}

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        
    	UserDetails userDetails = (UserDetails) authentication.getPrincipal();
    	
		Map<String, Object> tokenMap = new HashMap<String, Object>();
		tokenMap.put("code", "0");
		// 账号首次登陆标记
		if(SecurityPrincipal.class.isAssignableFrom(userDetails.getClass())) {
			tokenMap.put("initial", ((SecurityPrincipal) userDetails).isInitial());
		} else {
			tokenMap.put("initial", false);
		}
		tokenMap.put("perms", userDetails.getAuthorities());
		tokenMap.put("token", getPayloadRepository().issueJwt((JwtAuthenticationToken) authentication));
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
