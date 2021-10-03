package com.Yoo.jwt.config.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.Yoo.jwt.config.auth.PrincipalDetails;
import com.Yoo.jwt.model.User;
import com.Yoo.jwt.repository.UserRepository;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

// 시큐리티가 filter를 가지고 있는데 그 필터중에 BasicAuthenticationFilter 라는 것이 있음.
// 권한이나 인증이 필요한 특정 주소를 요청했을 때 위 필터를 무조건 타게 되어있음.
// 만약에 권한이나 인증이 필요한 주소가 아니라면 이 필터를 안탄다.
public class JwtAuthorizationFilter extends BasicAuthenticationFilter{
	
	private UserRepository userRepository;

	public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
		super(authenticationManager);
		this.userRepository = userRepository;
	}

	// 인증이나 권한이 필요한 주소요청이 있을 때 해당 필터를 타게됨.
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		//super.doFilterInternal(request, response, chain);  이게 있고, 또 , chain.doFilter 를 하면 응답이 두번이되기때문에 오류가 난다.
		System.out.println("인증이나 권한이 필요한 주소 요청이 됨.");
		
		String jwtHeader = request.getHeader("Authorization");
		System.out.println("jwtHeader : "+jwtHeader);
		
		// header가 있는지 확인
		if(jwtHeader == null || !(jwtHeader.startsWith("Bearer"))) {
			chain.doFilter(request, response);
			return;
		}
		// JWT 토큰을 검증을 해서 정상적인 사용자인지 확인!!
		String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");		//만들어진 token값중에 "Bearer "를  ""로 치환!!
		
		String username =
				JWT.require(Algorithm.HMAC512("cos")).build().verify(jwtToken).getClaim("username").asString();		//서명
		
		// 서명이 정상적으로 됨
		if(username != null) {
			User userEntity = userRepository.findByUsername(username);
			
			PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
			
			// Jwt 토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어준다.
			// 유저네임이 널이 아니라는 것은 정상적인 유저라는 것이기 때문에 강제로 Authentication을 만들어도 된다.
			Authentication authentication =
					new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());		//두번째 파라미터가 null 이 가능한 이유는 정상적인 유저라는 것이 때문에!!
			
			// 강제로 시큐리티의 세션에 접근하여 Authentication 객체를 만들어준다.
			SecurityContextHolder.getContext().setAuthentication(authentication);
			
			chain.doFilter(request, response);
		}
		
	}
}
