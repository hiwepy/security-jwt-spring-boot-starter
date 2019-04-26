package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.boot.biz.property.SecurityCaptchaProperties;
import org.springframework.security.boot.biz.property.SecurityLogoutProperties;
import org.springframework.security.boot.biz.property.SecurityRedirectProperties;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.jwt.property.SecurityJwtAuthcProperties;
import org.springframework.security.boot.jwt.property.SecurityJwtAuthzProperties;

@ConfigurationProperties(prefix = SecurityJwtProperties.PREFIX)
public class SecurityJwtProperties {

	public static final String PREFIX = "spring.security.jwt";

	/** Whether Enable JWT Authentication. */
	private boolean enabled = false;
	@NestedConfigurationProperty
	private SecurityJwtAuthcProperties authc = new SecurityJwtAuthcProperties();
	@NestedConfigurationProperty
	private SecurityCaptchaProperties captcha = new SecurityCaptchaProperties();
	@NestedConfigurationProperty
	private SecurityJwtAuthzProperties authz = new SecurityJwtAuthzProperties();
	@NestedConfigurationProperty
	private SecurityLogoutProperties logout = new SecurityLogoutProperties();
	@NestedConfigurationProperty
	private SecurityRedirectProperties redirect = new SecurityRedirectProperties();
	@NestedConfigurationProperty
	private SecuritySessionMgtProperties sessionMgt = new SecuritySessionMgtProperties();
	
	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public SecurityJwtAuthcProperties getAuthc() {
		return authc;
	}

	public void setAuthc(SecurityJwtAuthcProperties authc) {
		this.authc = authc;
	}

	public SecurityCaptchaProperties getCaptcha() {
		return captcha;
	}

	public void setCaptcha(SecurityCaptchaProperties captcha) {
		this.captcha = captcha;
	}

	public SecurityJwtAuthzProperties getAuthz() {
		return authz;
	}

	public void setAuthz(SecurityJwtAuthzProperties authz) {
		this.authz = authz;
	}

	public SecurityLogoutProperties getLogout() {
		return logout;
	}

	public void setLogout(SecurityLogoutProperties logout) {
		this.logout = logout;
	}

	public SecurityRedirectProperties getRedirect() {
		return redirect;
	}

	public void setRedirect(SecurityRedirectProperties redirect) {
		this.redirect = redirect;
	}

	public SecuritySessionMgtProperties getSessionMgt() {
		return sessionMgt;
	}

	public void setSessionMgt(SecuritySessionMgtProperties sessionMgt) {
		this.sessionMgt = sessionMgt;
	}

}
