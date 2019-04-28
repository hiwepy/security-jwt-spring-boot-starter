package org.springframework.security.boot.jwt.authentication;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.jwt.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.util.Assert;

import com.github.vindell.jwt.JwtPayload;

/**
 * 
 * Jwt授权 (authorization)处理器
 * @author 		： <a href="https://github.com/vindell">wandl</a>
 */
public class JwtAuthorizationProvider implements AuthenticationProvider {
	
	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
	private final Logger logger = LoggerFactory.getLogger(getClass());
	private final JwtPayloadRepository payloadRepository;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
    private boolean checkExpiry = true;
    
    public JwtAuthorizationProvider(final JwtPayloadRepository payloadRepository) {
        this.payloadRepository = payloadRepository;
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
		JwtAuthorizationToken jwtToken = (JwtAuthorizationToken) authentication;
		
		// 解析Token载体信息
		JwtPayload payload = getPayloadRepository().getPayload(jwtToken, checkExpiry);
		
		Set<GrantedAuthority> grantedAuthorities = new HashSet<GrantedAuthority>();
		
		// 用户角色ID集合
   		List<String> roles = Arrays.asList(StringUtils.tokenizeToStringArray(payload.getRoles()));
   		for (String role : roles) {
   			//角色必须是ROLE_开头，可以在数据库中设置
            GrantedAuthority grantedAuthority = new SimpleGrantedAuthority(StringUtils.startsWithIgnoreCase(role, "ROLE_") ?
            		role : "ROLE_"+role);
            grantedAuthorities.add(grantedAuthority);
		}
   		
   		// 用户权限标记集合
   		List<String> perms = Arrays.asList(StringUtils.tokenizeToStringArray(payload.getPerms()));
		for (String perm : perms ) {
			GrantedAuthority authority = new SimpleGrantedAuthority(perm);
            grantedAuthorities.add(authority);
		}
		
		SecurityPrincipal principal = new SecurityPrincipal(payload.getClientId(), payload.getTokenId(), payload.isEnabled(),
				payload.isAccountNonExpired(), payload.isCredentialsNonExpired(), payload.isAccountNonLocked(),
				grantedAuthorities);
		
		principal.setUserid(payload.getClientId());
		principal.setAlias(payload.getAlias());
		principal.setPerms(new HashSet<String>());
		principal.setRoles(new HashSet<String>(roles));
        
        // User Status Check
        getUserDetailsChecker().check(principal);
        
        JwtAuthorizationToken authenticationToken = new JwtAuthorizationToken(principal, payload, principal.getAuthorities());        	
        authenticationToken.setDetails(authentication.getDetails());
        
        return authenticationToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (JwtAuthorizationToken.class.isAssignableFrom(authentication));
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
