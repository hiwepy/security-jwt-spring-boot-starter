package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.boot.biz.property.SecurityCaptchaProperties;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.jwt.property.SecurityJwtAuthcProperties;
import org.springframework.security.boot.jwt.property.SecurityJwtAuthzProperties;

@ConfigurationProperties(prefix = SecurityJwtProperties.PREFIX)
public class SecurityJwtProperties {

	public static final String PREFIX = "spring.security.jwt";

	@NestedConfigurationProperty
	private SecurityJwtAuthcProperties authc = new SecurityJwtAuthcProperties();
	@NestedConfigurationProperty
	private SecurityCaptchaProperties captcha = new SecurityCaptchaProperties();
	@NestedConfigurationProperty
	private SecurityJwtAuthzProperties authz = new SecurityJwtAuthzProperties();
	@NestedConfigurationProperty
	private SecuritySessionMgtProperties sessionMgt = new SecuritySessionMgtProperties();
	
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

	public SecuritySessionMgtProperties getSessionMgt() {
		return sessionMgt;
	}

	public void setSessionMgt(SecuritySessionMgtProperties sessionMgt) {
		this.sessionMgt = sessionMgt;
	}

}
