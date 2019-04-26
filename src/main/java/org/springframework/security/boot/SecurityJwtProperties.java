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
	
	@NestedConfigurationProperty
	private SecurityCaptchaProperties captcha = new SecurityCaptchaProperties();
	@NestedConfigurationProperty
	private SecurityLogoutProperties logout = new SecurityLogoutProperties();
	@NestedConfigurationProperty
	private SecurityRedirectProperties redirect = new SecurityRedirectProperties();
	@NestedConfigurationProperty
	private SecuritySessionMgtProperties sessionMgt = new SecuritySessionMgtProperties();

	public SecurityCaptchaProperties getCaptcha() {
		return captcha;
	}

	public void setCaptcha(SecurityCaptchaProperties captcha) {
		this.captcha = captcha;
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
