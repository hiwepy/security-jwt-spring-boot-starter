package org.springframework.security.boot.jwt.exception;

import org.springframework.security.core.AuthenticationException;

public class JwtIncorrectException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>AuthTokenIncorrectException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public JwtIncorrectException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>AuthTokenIncorrectException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public JwtIncorrectException(String msg, Throwable t) {
		super(msg, t);
	}
}
