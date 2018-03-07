package org.springframework.security.boot.jwt.endpoint;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.boot.SecurityJwtProperties;
import org.springframework.security.boot.jwt.authentication.jwt.extractor.TokenExtractor;
import org.springframework.security.boot.jwt.authentication.jwt.verifier.TokenVerifier;
import org.springframework.security.boot.jwt.exception.InvalidJwtToken;
import org.springframework.security.boot.jwt.model.UserContext;
import org.springframework.security.boot.jwt.token.JwtToken;
import org.springframework.security.boot.jwt.token.JwtTokenFactory;
import org.springframework.security.boot.jwt.token.RawAccessJwtToken;
import org.springframework.security.boot.jwt.token.RefreshToken;
import org.springframework.security.boot.jwt.userdetails.UserService;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;


/**
 * RefreshTokenEndpoint
 * 
 * @author vladimir.stankovic
 *
 * Aug 17, 2016
 */
@RestController
public class RefreshTokenEndpoint {
	
    @Autowired 
    private JwtTokenFactory tokenFactory;
    @Autowired 
    private SecurityJwtProperties jwtSettings;
    @Autowired 
    private UserService userService;
    @Autowired 
    private TokenVerifier tokenVerifier;
    @Autowired 
    @Qualifier("jwtHeaderTokenExtractor") 
    private TokenExtractor tokenExtractor;
    
    @RequestMapping(value="/api/auth/token", method=RequestMethod.GET, produces={ MediaType.APPLICATION_JSON_VALUE })
    public @ResponseBody JwtToken refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        String tokenPayload = tokenExtractor.extract(request.getHeader(jwtSettings.getTokenHeaderName()));
        
        RawAccessJwtToken rawToken = new RawAccessJwtToken(tokenPayload);
        RefreshToken refreshToken = RefreshToken.create(rawToken, jwtSettings.getTokenSigningKey()).orElseThrow(() -> new InvalidJwtToken());

        String jti = refreshToken.getJti();
        if (!tokenVerifier.verify(jti)) {
            throw new InvalidJwtToken();
        }

        String subject = refreshToken.getSubject();
        User user = userService.getByUsername(subject).orElseThrow(() -> new UsernameNotFoundException("User not found: " + subject));

        if (user.getRoles() == null) throw new InsufficientAuthenticationException("User has no roles assigned");
        List<GrantedAuthority> authorities = user.getRoles().stream()
                .map(authority -> new SimpleGrantedAuthority(authority.getRole().authority()))
                .collect(Collectors.toList());

        UserContext userContext = UserContext.create(user.getUsername(), authorities);

        return tokenFactory.createAccessJwtToken(userContext);
    }
}
