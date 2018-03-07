package org.springframework.security.boot.jwt.userdetails;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * 提供认证所需的用户信息
 *
 * @author ybin
 * @since 2017-03-08
 */
public class JwtUserDetailsService implements UserDetailsService {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // 1. 根据用户标识获取用户

        if (username == null) {
            logger.debug("can not find user: " + username);
            throw new UsernameNotFoundException("can not find user.");
        }

        // 2. 获取用户权限

        UserDetails userDetails = new JWTUserDetails(userId, username, password,
                enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);

        return userDetails;
    }

}