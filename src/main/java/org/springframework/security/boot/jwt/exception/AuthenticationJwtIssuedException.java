package org.springframework.security.boot.jwt.exception;

import org.springframework.security.core.AuthenticationException;

@SuppressWarnings("serial")
public class AuthenticationJwtIssuedException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>AuthenticationJwtIssuedException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public AuthenticationJwtIssuedException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>AuthenticationJwtIssuedException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public AuthenticationJwtIssuedException(String msg, Throwable t) {
		super(msg, t);
	}

}
