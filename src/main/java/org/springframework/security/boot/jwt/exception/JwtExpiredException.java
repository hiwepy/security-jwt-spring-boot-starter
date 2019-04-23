package org.springframework.security.boot.jwt.exception;

import org.springframework.security.core.AuthenticationException;

public class JwtExpiredException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>AuthTokenExpiredException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public JwtExpiredException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>AuthTokenExpiredException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public JwtExpiredException(String msg, Throwable t) {
		super(msg, t);
	}

}
