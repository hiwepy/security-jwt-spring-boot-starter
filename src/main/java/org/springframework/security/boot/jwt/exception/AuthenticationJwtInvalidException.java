package org.springframework.security.boot.jwt.exception;

import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.exception.AuthenticationExceptionAdapter;
@SuppressWarnings("serial")
public class AuthenticationJwtInvalidException extends AuthenticationExceptionAdapter {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>AuthenticationJwtInvalidException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public AuthenticationJwtInvalidException(String msg) {
		super(AuthResponseCode.SC_AUTHZ_TOKEN_INVALID, msg);
	}

	/**
	 * Constructs an <code>AuthenticationJwtInvalidException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public AuthenticationJwtInvalidException(String msg, Throwable t) {
		super(AuthResponseCode.SC_AUTHZ_TOKEN_INVALID, msg, t);
	}

}
