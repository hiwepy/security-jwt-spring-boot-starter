package org.springframework.security.boot.jwt.authentication;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import com.alibaba.fastjson.JSONObject;

/**
 * TODO
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public class JwtAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
   
	private List<AuthenticationListener> authenticationListeners;
	
	public JwtAuthenticationSuccessHandler(List<AuthenticationListener> authenticationListeners, String defaultTargetUrl) {
		this.setAuthenticationListeners(authenticationListeners);
	}

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        
		//调用事件监听器
		if(getAuthenticationListeners() != null && getAuthenticationListeners().size() > 0){
			for (AuthenticationListener authenticationListener : getAuthenticationListeners()) {
				authenticationListener.onSuccess(request, response, authentication);
			}
		}
		
    	UserDetails userDetails = (UserDetails) authentication.getPrincipal();
    	
		Map<String, Object> tokenMap = new HashMap<String, Object>();
		tokenMap.put("perms", userDetails.getAuthorities());
		tokenMap.put("status", "1");
		//tokenMap.put("token", getDefaultTargetUrl());
		tokenMap.put("username", userDetails.getUsername());

		response.setStatus(HttpStatus.OK.value());
		response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
		
		JSONObject.writeJSONString(response.getWriter(), tokenMap);

		clearAuthenticationAttributes(request);
    	 
    }

    /**
     * Removes temporary authentication-related data which may have been stored
     * in the session during the authentication process..
     * 
     */
    protected final void clearAuthenticationAttributes(HttpServletRequest request) {
        HttpSession session = request.getSession(false);

        if (session == null) {
            return;
        }

        session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
    }
    

	public List<AuthenticationListener> getAuthenticationListeners() {
		return authenticationListeners;
	}

	public void setAuthenticationListeners(List<AuthenticationListener> authenticationListeners) {
		this.authenticationListeners = authenticationListeners;
	}
}
