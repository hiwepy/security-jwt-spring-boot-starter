package org.springframework.security.boot.jwt.exception;

import org.springframework.security.core.AuthenticationException;
@SuppressWarnings("serial")
public class AuthenticationJwtNotFoundException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>JwtNotFoundException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public AuthenticationJwtNotFoundException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>JwtNotFoundException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public AuthenticationJwtNotFoundException(String msg, Throwable t) {
		super(msg, t);
	}

}
