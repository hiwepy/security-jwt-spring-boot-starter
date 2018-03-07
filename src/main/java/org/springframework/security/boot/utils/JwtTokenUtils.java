package org.springframework.security.boot.utils;

import java.io.IOException;
import java.security.Key;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Collectors;

import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.boot.SecurityJwtProperties;
import org.springframework.security.boot.jwt.model.Scopes;
import org.springframework.security.boot.jwt.model.UserContext;
import org.springframework.security.boot.jwt.token.AccessJwtToken;
import org.springframework.security.boot.jwt.token.JwtToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * 
 * @className	： JwtTokenUtils
 * @description	： TODO(描述这个类的作用)
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 * @date		： 2017年9月13日 下午7:14:57
 * @version 	V1.0
 */
public class JwtTokenUtils {

	protected static ConcurrentMap<String /* Key */, JwtTokenUtil> COMPLIED_UTILS = new ConcurrentHashMap<String, JwtTokenUtil>();

	public static final String ROLE_REFRESH_TOKEN = "ROLE_REFRESH_TOKEN";
	public static final String CLAIM_KEY_USER_ID = "user_id";
	public static final String CLAIM_KEY_AUTHORITIES = "scope";
	public static final String CLAIM_KEY_ACCOUNT_ENABLED = "enabled";
	public static final String CLAIM_KEY_ACCOUNT_NON_LOCKED = "non_locked";
	public static final String CLAIM_KEY_ACCOUNT_NON_EXPIRED = "non_expired";

	public long getUserIdFromToken(String token) {
		long userId;
		try {
			final Claims claims = getClaimsFromToken(token);
			userId = (Long) claims.get(CLAIM_KEY_USER_ID);
		} catch (Exception e) {
			userId = 0;
		}
		return userId;
	}

	public String getUsernameFromToken(String token) {
		String username;
		try {
			final Claims claims = getClaimsFromToken(token);
			username = claims.getSubject();
		} catch (Exception e) {
			username = null;
		}
		return username;
	}

	public Date getCreatedDateFromToken(String token) {
		Date created;
		try {
			final Claims claims = getClaimsFromToken(token);
			created = claims.getIssuedAt();
		} catch (Exception e) {
			created = null;
		}
		return created;
	}

	public Date getExpirationDateFromToken(String token) {
		Date expiration;
		try {
			final Claims claims = getClaimsFromToken(token);
			expiration = claims.getExpiration();
		} catch (Exception e) {
			expiration = null;
		}
		return expiration;
	}

	public Claims getClaimsFromToken(String token) {
		Claims claims;
		try {
			// 解析jwt串 :其中parseClaimsJws验证jwt字符串失败可能会抛出异常，需要捕获异常
			claims = Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody(); // 得到body后我们可以从body中获取我们需要的信息
		} catch (Exception e) {
			// jwt 解析错误
			claims = null;
		}
		return claims;
	}

	public Date generateExpirationDate(long expiration) {
		return new Date(System.currentTimeMillis() + expiration * 1000);
	}

	public Boolean isTokenExpired(String token) {
		final Date expiration = getExpirationDateFromToken(token);
		return expiration.before(new Date());
	}

	public Boolean isCreatedBeforeLastPasswordReset(Date created, Date lastPasswordReset) {
		return (lastPasswordReset != null && created.before(lastPasswordReset));
	}

	public Claims parseJWT(String jsonWebToken, String base64Security) {
		try {
			Claims claims = Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary(base64Security))
					.parseClaimsJws(jsonWebToken).getBody();
			return claims;
		} catch (Exception ex) {
			return null;
		}
	}

	public String createJWT(String name, String userId, String role, String audience, String issuer, long TTLMillis,
			String base64Security) {

		long nowMillis = System.currentTimeMillis();
		Date now = new Date(nowMillis);

		// 生成签名密钥
		byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(base64Security);
		Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());

		// 添加构成JWT的参数
		JwtBuilder builder = Jwts.builder().setHeaderParam("typ", "JWT").claim("role", role).claim("unique_name", name)
				.claim("userid", userId).setIssuer(issuer).setAudience(audience)
				.signWith(signatureAlgorithm, signingKey);
		// 添加Token过期时间
		if (TTLMillis >= 0) {
			long expMillis = nowMillis + TTLMillis;
			Date exp = new Date(expMillis);
			builder.setExpiration(exp).setNotBefore(now);
		}

		// 生成JWT
		return builder.compact();
	}

	public String generateAccessToken(String subject, Map<String, Object> claims) {
		return generateToken(subject, claims, accessTokenExpiration);
	}

	public String generateRefreshToken(String subject, Map<String, Object> claims) {
		return generateToken(subject, claims, refreshTokenExpiration);
	}

	public Boolean canTokenBeRefreshed(String token, Date lastPasswordReset) {
		final Date created = getCreatedDateFromToken(token);
		return !isCreatedBeforeLastPasswordReset(created, lastPasswordReset) && (!isTokenExpired(token));
	}

	public String refreshToken(String token) {
		String refreshedToken;
		try {
			final Claims claims = getClaimsFromToken(token);
			refreshedToken = generateAccessToken(claims.getSubject(), claims);
		} catch (Exception e) {
			refreshedToken = null;
		}
		return refreshedToken;
	}

	private String generateToken(String subject, Map<String, Object> claims, long expiration) {
		return Jwts.builder().setClaims(claims).setSubject(subject) // 设置主题
				.setId(UUID.randomUUID().toString()).setIssuedAt(new Date())
				.setExpiration(generateExpirationDate(expiration)).compressWith(CompressionCodecs.DEFLATE)
				.signWith(signatureAlgorithm, secret) // 设置算法（必须）
				.compact();
	}
	
	
	public static JwtTokenUtil jwtTokenUtil(String secret) {
		return jwtTokenUtil(secret, SignatureAlgorithm.HS256, -1L, -1L);
	}
	
	public static JwtTokenUtil jwtTokenUtil(String secret, SignatureAlgorithm signatureAlgorithm) {
		return jwtTokenUtil(secret, signatureAlgorithm, -1L, -1L);
	}
	
	public static JwtTokenUtil jwtTokenUtil(String secret, SignatureAlgorithm signatureAlgorithm,
			Long accessTokenExpiration, Long refreshTokenExpiration) {
		String key = new StringBuilder(secret).append(".").append(signatureAlgorithm.getValue()).append(".")
				.append(accessTokenExpiration).append(".").append(refreshTokenExpiration).toString();
		if (StringUtils.isNotEmpty(key)) {
			JwtTokenUtil ret = COMPLIED_UTILS.get(key);
			if (ret != null) {
				return ret;
			}
			ret = new JwtTokenUtil(secret, signatureAlgorithm, accessTokenExpiration, refreshTokenExpiration);
			JwtTokenUtil existing = COMPLIED_UTILS.putIfAbsent(key, ret);
			if (existing != null) {
				ret = existing;
			}
			return ret;
		}
		return null;
	}
	
	 /**
     * Factory method for issuing new JWT Tokens.
     * 
     * @param username
     * @param roles
     * @return
     */
    public static AccessJwtToken createAccessJwtToken(SecurityJwtProperties jwtProperties, UserContext userContext) {
        if (StringUtils.isBlank(userContext.getUsername())) 
            throw new IllegalArgumentException("Cannot create JWT Token without username");

        if (userContext.getAuthorities() == null || userContext.getAuthorities().isEmpty()) 
            throw new IllegalArgumentException("User doesn't have any privileges");

        Claims claims = Jwts.claims().setSubject(userContext.getUsername());
        claims.put("scopes", userContext.getAuthorities().stream().map(s -> s.toString()).collect(Collectors.toList()));

        LocalDateTime currentTime = LocalDateTime.now();
        
        String token = Jwts.builder()
          .setClaims(claims)
          .setIssuer(jwtProperties.getTokenIssuer())
          .setIssuedAt(Date.from(currentTime.atZone(ZoneId.systemDefault()).toInstant()))
          .setExpiration(Date.from(currentTime
              .plusMinutes(jwtProperties.getTokenExpirationTime())
              .atZone(ZoneId.systemDefault()).toInstant()))
          .signWith(SignatureAlgorithm.HS512, jwtProperties.getTokenSigningKey())
        .compact();

        return new AccessJwtToken(token, claims);
    }

    public static JwtToken createRefreshToken(SecurityJwtProperties jwtProperties, UserContext userContext) {
        if (StringUtils.isBlank(userContext.getUsername())) {
            throw new IllegalArgumentException("Cannot create JWT Token without username");
        }

        LocalDateTime currentTime = LocalDateTime.now();

        Claims claims = Jwts.claims().setSubject(userContext.getUsername());
        claims.put("scopes", Arrays.asList(Scopes.REFRESH_TOKEN.authority()));
        
        String token = Jwts.builder()
          .setClaims(claims)
          .setIssuer(jwtProperties.getTokenIssuer())
          .setId(UUID.randomUUID().toString())
          .setIssuedAt(Date.from(currentTime.atZone(ZoneId.systemDefault()).toInstant()))
          .setExpiration(Date.from(currentTime
              .plusMinutes(jwtProperties.getRefreshTokenExpTime())
              .atZone(ZoneId.systemDefault()).toInstant()))
          .signWith(SignatureAlgorithm.HS512, jwtProperties.getTokenSigningKey())
        .compact();

        return new AccessJwtToken(token, claims);
    }
	
}
