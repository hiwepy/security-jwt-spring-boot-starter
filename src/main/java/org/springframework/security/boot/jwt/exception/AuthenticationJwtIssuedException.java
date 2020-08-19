package org.springframework.security.boot.jwt.exception;

import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.exception.AuthenticationExceptionAdapter;

@SuppressWarnings("serial")
public class AuthenticationJwtIssuedException extends AuthenticationExceptionAdapter {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>AuthenticationJwtIssuedException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public AuthenticationJwtIssuedException(String msg) {
		super(AuthResponseCode.SC_AUTHZ_TOKEN_ISSUED, msg);
	}

	/**
	 * Constructs an <code>AuthenticationJwtIssuedException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public AuthenticationJwtIssuedException(String msg, Throwable t) {
		super(AuthResponseCode.SC_AUTHZ_TOKEN_ISSUED,msg, t);
	}

}
