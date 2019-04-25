package org.springframework.security.boot.jwt.authentication;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.boot.biz.userdetails.BaseAuthenticationUserDetailsService;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.jwt.userdetails.JwtUserDetails;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * 
 * Jwt授权 (authorization)处理器
 * @author 		： <a href="https://github.com/vindell">wandl</a>
 */
public class JwtAuthorizationProvider implements AuthenticationProvider {
	
	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
	private final Logger logger = LoggerFactory.getLogger(getClass());
    private final BaseAuthenticationUserDetailsService userDetailsService;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
    
    public JwtAuthorizationProvider(final BaseAuthenticationUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    /**
     * 
     * <p>完成匹配Token的认证，这里返回的对象最终会通过：SecurityContextHolder.getContext().setAuthentication(authResult); 放置在上下文中</p>
     * @author 		：<a href="https://github.com/vindell">wandl</a>
     * @param authentication  {@link JwtAuthenticationToken} 对象
     * @return 认证结果{@link JwtAuthenticationToken}对象
     * @throws AuthenticationException 认证失败会抛出异常
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        
    	Assert.notNull(authentication, "No authentication data provided");
    	
    	if (logger.isDebugEnabled()) {
			logger.debug("Processing authentication request : " + authentication);
		}
 
        String token = (String) authentication.getPrincipal();
        
		if (!StringUtils.hasLength(token)) {
			logger.debug("No principal found in request.");
			throw new BadCredentialsException("No principal found in request.");
		}
        
		JwtUserDetails ud = (JwtUserDetails) userDetailsService.loadUserDetails(authentication);
        
        // User Status Check
        getUserDetailsChecker().check(ud);
        
        JwtAuthorizationToken authenticationToken = null;
        if(SecurityPrincipal.class.isAssignableFrom(ud.getClass())) {
        	authenticationToken = new JwtAuthorizationToken(ud, ud.getPayload(), ud.getAuthorities());        	
        } else {
        	authenticationToken = new JwtAuthorizationToken(ud.getUsername(), ud.getPayload(), ud.getAuthorities());
		}
        authenticationToken.setDetails(authentication.getDetails());
        
        return authenticationToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (JwtAuthenticationToken.class.isAssignableFrom(authentication));
    }
    
    public void setUserDetailsChecker(UserDetailsChecker userDetailsChecker) {
		this.userDetailsChecker = userDetailsChecker;
	}

	public UserDetailsChecker getUserDetailsChecker() {
		return userDetailsChecker;
	}
    
}
