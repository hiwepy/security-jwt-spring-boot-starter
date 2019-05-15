package org.springframework.security.boot.jwt.exception;

import org.springframework.security.core.AuthenticationException;
@SuppressWarnings("serial")
public class AuthenticationJwtInvalidException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>JwtInvalidException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public AuthenticationJwtInvalidException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>JwtInvalidException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public AuthenticationJwtInvalidException(String msg, Throwable t) {
		super(msg, t);
	}

}
