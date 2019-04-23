package org.springframework.security.boot.jwt.authentication;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Jwt授权 (authorization) Token
 * @author ： <a href="https://github.com/vindell">vindell</a>
 */
@SuppressWarnings("serial")
public class JwtAuthorizationToken extends AbstractAuthenticationToken {

    private String token;
    private UserDetails userDetails;

    public JwtAuthorizationToken(String token) {
        super(null);
        this.token = token;
        this.setAuthenticated(false);
    }

    public JwtAuthorizationToken(UserDetails userDetails, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.eraseCredentials();
        this.userDetails = userDetails;
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
        return token;
    }

    @Override
    public Object getPrincipal() {
        return this.userDetails;
    }

    @Override
    public void eraseCredentials() {        
        super.eraseCredentials();
        this.token = null;
    }
    
}
