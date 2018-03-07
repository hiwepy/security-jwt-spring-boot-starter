package org.springframework.security.boot.jwt.authentication.jwt;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationToken;
import org.springframework.security.boot.jwt.model.UserContext;
import org.springframework.security.boot.jwt.token.JwtToken;
import org.springframework.security.boot.jwt.token.RawAccessJwtToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;

/**
 * An {@link AuthenticationProvider} implementation that will use provided
 * instance of {@link JwtToken} to perform authentication.
 * 
 * @author vladimir.stankovic
 * @author vindell
 *
 * Aug 5, 2016
 */
@SuppressWarnings("unchecked")
public class JwtAuthenticationProvider implements AuthenticationProvider {
	
	/**
     * Key is used to sign {@link JwtToken}.
     */
    private final String tokenSigningKey;
    
    public JwtAuthenticationProvider(String tokenSigningKey) {
        this.tokenSigningKey = tokenSigningKey;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    	
        RawAccessJwtToken rawAccessToken = (RawAccessJwtToken) authentication.getCredentials();

        Jws<Claims> jwsClaims = rawAccessToken.parseClaims(tokenSigningKey);
        String subject = jwsClaims.getBody().getSubject();
        List<String> scopes = jwsClaims.getBody().get("scopes", List.class);
        List<GrantedAuthority> authorities = scopes.stream()
                .map(authority -> new SimpleGrantedAuthority(authority))
                .collect(Collectors.toList());
        
        UserContext context = UserContext.create(subject, authorities);
        
        return new JwtAuthenticationToken(context, context.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (JwtAuthenticationToken.class.isAssignableFrom(authentication));
    }
    
}
