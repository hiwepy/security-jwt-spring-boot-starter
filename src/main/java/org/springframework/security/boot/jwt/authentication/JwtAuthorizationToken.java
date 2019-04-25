package org.springframework.security.boot.jwt.authentication;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

/**
 * Jwt授权 (authorization) Token
 * @author ： <a href="https://github.com/vindell">vindell</a>
 */
@SuppressWarnings("serial")
public class JwtAuthorizationToken extends AbstractAuthenticationToken {

	private final Object principal;
	private Object credentials;
    
    public JwtAuthorizationToken( Object principal) {
        super(null);
        this.principal = principal;
        this.setAuthenticated(false);
    }

    public JwtAuthorizationToken( Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.eraseCredentials();
        this.principal = principal;
        this.credentials = credentials;
        super.setAuthenticated(true);
    }

    @Override
    public void setAuthenticated(boolean authenticated) {
        if (authenticated) {
            throw new IllegalArgumentException(
                    "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        }
        super.setAuthenticated(false);
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }
    
    @Override
    public void eraseCredentials() {        
        super.eraseCredentials();
        this.credentials = null;
    }
    
}
