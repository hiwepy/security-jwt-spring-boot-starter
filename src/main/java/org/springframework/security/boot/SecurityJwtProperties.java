package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.boot.web.servlet.filter.OrderedFilter;
import org.springframework.security.boot.biz.property.SecurityAuthcProperties;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@ConfigurationProperties(prefix = SecurityJwtProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityJwtProperties {
	
	public static final int FILTER_ORDER = OrderedFilter.REQUEST_WRAPPER_FILTER_MAX_ORDER - 100;
	
	public static final String PREFIX = "spring.security.jwt";
	/** Whether Enable JWT . */
	private boolean enabled = false;
	
	@NestedConfigurationProperty
	private SecurityAuthcProperties authc = new SecurityAuthcProperties();

}
