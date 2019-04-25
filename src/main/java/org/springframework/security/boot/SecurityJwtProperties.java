package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.boot.jwt.property.SecurityJwtAuthcProperties;
import org.springframework.security.boot.jwt.property.SecurityJwtAuthzProperties;

@ConfigurationProperties(prefix = SecurityJwtProperties.PREFIX)
public class SecurityJwtProperties {

	public static final String PREFIX = "spring.security.jwt";

	@NestedConfigurationProperty
	private SecurityJwtAuthcProperties authc = new SecurityJwtAuthcProperties();
	@NestedConfigurationProperty
	private SecurityJwtAuthzProperties authz = new SecurityJwtAuthzProperties();

	public SecurityJwtAuthcProperties getAuthc() {
		return authc;
	}

	public void setAuthc(SecurityJwtAuthcProperties authc) {
		this.authc = authc;
	}

	public SecurityJwtAuthzProperties getAuthz() {
		return authz;
	}

	public void setAuthz(SecurityJwtAuthzProperties authz) {
		this.authz = authz;
	}

}
