package org.springframework.security.boot.jwt.exception;

import org.springframework.security.core.AuthenticationException;

@SuppressWarnings("serial")
public class AuthenticationJwtExpiredException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>AuthenticationJwtExpiredException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public AuthenticationJwtExpiredException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>AuthenticationJwtExpiredException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public AuthenticationJwtExpiredException(String msg, Throwable t) {
		super(msg, t);
	}

}
