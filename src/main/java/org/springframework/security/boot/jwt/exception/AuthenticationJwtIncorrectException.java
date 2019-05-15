package org.springframework.security.boot.jwt.exception;

import org.springframework.security.core.AuthenticationException;
@SuppressWarnings("serial")
public class AuthenticationJwtIncorrectException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>AuthenticationJwtIncorrectException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public AuthenticationJwtIncorrectException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>AuthenticationJwtIncorrectException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public AuthenticationJwtIncorrectException(String msg, Throwable t) {
		super(msg, t);
	}
}
