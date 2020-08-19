package org.springframework.security.boot.jwt.exception;

import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.exception.AuthenticationExceptionAdapter;

@SuppressWarnings("serial")
public class AuthenticationJwtExpiredException extends AuthenticationExceptionAdapter {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>AuthenticationJwtExpiredException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public AuthenticationJwtExpiredException(String msg) {
		super(AuthResponseCode.SC_AUTHZ_TOKEN_EXPIRED, msg);
	}

	/**
	 * Constructs an <code>AuthenticationJwtExpiredException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public AuthenticationJwtExpiredException(String msg, Throwable t) {
		super(AuthResponseCode.SC_AUTHZ_TOKEN_EXPIRED, msg, t);
	}

}
