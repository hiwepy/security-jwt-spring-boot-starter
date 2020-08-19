package org.springframework.security.boot.jwt.exception;

import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.exception.AuthenticationExceptionAdapter;
@SuppressWarnings("serial")
public class AuthenticationJwtNotFoundException extends AuthenticationExceptionAdapter {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>AuthenticationJwtNotFoundException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public AuthenticationJwtNotFoundException(String msg) {
		super(AuthResponseCode.SC_AUTHZ_TOKEN_REQUIRED,msg);
	}

	/**
	 * Constructs an <code>AuthenticationJwtNotFoundException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public AuthenticationJwtNotFoundException(String msg, Throwable t) {
		super(AuthResponseCode.SC_AUTHZ_TOKEN_REQUIRED,msg, t);
	}

}
