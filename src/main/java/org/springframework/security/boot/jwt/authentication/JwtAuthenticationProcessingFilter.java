package org.springframework.security.boot.jwt.authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationProcessingFilter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Jwt认证 (authentication)过滤器
 * @author ： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class JwtAuthenticationProcessingFilter extends PostRequestAuthenticationProcessingFilter {
	
	public static final String DEFAULT_LONGITUDE_LATITUDE = "0.000000";
	
	/**
	 * HTTP Authorization header, equal to <code>X-Sign</code>
	 */
	public static final String SIGN_HEADER = "X-Sign";
	/**
	 * HTTP Authorization header, equal to <code>X-Longitude</code>
	 */
	public static final String LONGITUDE_HEADER = "X-Longitude";
	/**
	 * HTTP Authorization header, equal to <code>X-Latitude</code>
	 */
	public static final String LATITUDE_HEADER = "X-Latitude";
	private String signHeaderName = SIGN_HEADER;
	private String longitudeHeaderName = LONGITUDE_HEADER;
	private String latitudeHeaderName = LATITUDE_HEADER;
	
	
	public JwtAuthenticationProcessingFilter(ObjectMapper objectMapper) {
		super(objectMapper, new AntPathRequestMatcher("/login/jwt", "POST"));
	}
	
	
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		ServletRequestAttributes requestAttributes = new ServletRequestAttributes(request, response);
		RequestContextHolder.setRequestAttributes(requestAttributes, true);
		return super.attemptAuthentication(request, response);
	}
	
	@Override
	protected void setDetails(HttpServletRequest request, AbstractAuthenticationToken authRequest) {
		super.setDetails(request, authRequest);
		JwtAuthenticationToken jwtToken = (JwtAuthenticationToken) authRequest;
		jwtToken.setLongitude(this.obtainLongitude(request));
		jwtToken.setLatitude(this.obtainLatitude(request));
		jwtToken.setSign(this.obtainSign(request));
	}
	
	@Override
	protected AbstractAuthenticationToken authenticationToken(String username, String password) {
		return new JwtAuthenticationToken( username, password);
	}
	
	protected double obtainLongitude(HttpServletRequest request) {
		return Double.parseDouble(StringUtils.defaultIfBlank(request.getHeader(getLongitudeHeaderName()), DEFAULT_LONGITUDE_LATITUDE));
	}
	
	protected double obtainLatitude(HttpServletRequest request) {
		return Double.parseDouble(StringUtils.defaultIfBlank(request.getHeader(getLatitudeHeaderName()), DEFAULT_LONGITUDE_LATITUDE));
	}
	
	protected String obtainSign(HttpServletRequest request) {
		return request.getHeader(getSignHeaderName());
	}
	
	public String getSignHeaderName() {
		return signHeaderName;
	}

	public void setSignHeaderName(String signHeaderName) {
		this.signHeaderName = signHeaderName;
	}

	public String getLongitudeHeaderName() {
		return longitudeHeaderName;
	}

	public void setLongitudeHeaderName(String longitudeHeaderName) {
		this.longitudeHeaderName = longitudeHeaderName;
	}

	public String getLatitudeHeaderName() {
		return latitudeHeaderName;
	}

	public void setLatitudeHeaderName(String latitudeHeaderName) {
		this.latitudeHeaderName = latitudeHeaderName;
	}
}
