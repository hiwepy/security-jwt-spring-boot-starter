package org.springframework.security.boot.jwt.userdetails;

import java.util.Optional;

/**
 * 
 * @author vladimir.stankovic
 *
 * Aug 17, 2016
 */
public interface UserService {
    public Optional<User> getByUsername(String username);
}
