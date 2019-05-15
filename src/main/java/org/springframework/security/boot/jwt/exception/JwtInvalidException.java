package org.springframework.security.boot.jwt.exception;

import org.springframework.security.core.AuthenticationException;
@SuppressWarnings("serial")
public class JwtInvalidException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>JwtInvalidException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public JwtInvalidException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>JwtInvalidException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public JwtInvalidException(String msg, Throwable t) {
		super(msg, t);
	}

}
