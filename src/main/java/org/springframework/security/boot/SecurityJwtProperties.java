package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.boot.biz.property.SecurityAuthcProperties;
import org.springframework.security.boot.biz.property.SecurityLogoutProperties;

@ConfigurationProperties(prefix = SecurityJwtProperties.PREFIX)
public class SecurityJwtProperties {

	public static final String PREFIX = "spring.security.jwt";
	/** Whether Enable JWT . */
	private boolean enabled = false;
	
	@NestedConfigurationProperty
	private SecurityAuthcProperties authc = new SecurityAuthcProperties();
	@NestedConfigurationProperty
	private SecurityLogoutProperties logout = new SecurityLogoutProperties();
	
	public SecurityAuthcProperties getAuthc() {
		return authc;
	}

	public void setAuthc(SecurityAuthcProperties authc) {
		this.authc = authc;
	}

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public SecurityLogoutProperties getLogout() {
		return logout;
	}

	public void setLogout(SecurityLogoutProperties logout) {
		this.logout = logout;
	}

}
