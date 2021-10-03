package com.Yoo.jwt.config.jwt;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.Yoo.jwt.config.auth.PrincipalDetails;
import com.Yoo.jwt.model.User;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

// 스프링시큐리티에서 UsernamePasswordAuthenticationFilter 가 있음.
// /login 요청해서 username, password를 post로 전송하면
// UsernamePasswordAuthenticationFilter가 동작을 함. 원래 기본적인 필터이지만 formlogin.disable을 해서 동작을 안했다.
// 따라서 JwtAuthenticationFilter 필터를 다시 시큐리티 필터에 등록해줘야한다.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter{

	//파라미터를 받아왔다. DI 통해?
	private final AuthenticationManager authenticationManager;

	// authenticationManager를 통해 로그인 시도를 하는데 이때 실행되는 함수  :  attemptAuthentication
	// /login 요청을 하면 로그인 시도를 위해서 실행되는 함수.
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("JwtAuthenticationFilter : 로그인 시도중");
		
		// 1. username,password 를 받아서	// 일반적으로 json으로 로그인 요청을 한다고 가정하고 json으로 처리한다.
		try {
//			BufferedReader br = request.getReader();
//			
//			String input = null;
//			while((input=br.readLine()) != null) {
//				System.out.println(input); 
//			}
			ObjectMapper om = new ObjectMapper();
			User user = om.readValue(request.getInputStream(), User.class);	//이렇게 적으면 User 오브젝트에 담겨진다.
			System.out.println(user);
			
			UsernamePasswordAuthenticationToken authenticationToken =
					new UsernamePasswordAuthenticationToken(user.getUsername(),user.getPassword());
			
			// 이게 실행될때 PrincipalDetailsService 의 loadUserByUsername() 함수가 실행됨.  authentication 에 내 로그인한 정보가 저장됨. 이게 정상이면 Authentication이 리턴됨.
			// DB에 있는 username과 password가 일치한다.
			Authentication authentication =
					authenticationManager.authenticate(authenticationToken);
			
			PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();
			System.out.println("로그인 완료됨?"+principalDetails.getUser().getUsername());	// 확인할 수 있다는 것은 로그인이 정상적으로 되었다는 뜻.
			
			// authentication 객체가 session 영역에 저장을 해여하고 그 방법이 return해주면됨.
			// 리턴의 이유는 권한 관리를 security가 대신 해주기 떄문에 편하려고 하는거임.
			// 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없지만 단지 권한 처리때문에 session에 넣어준다.
			return authentication;		//session에 저장이된다.
			
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return null;
		//return super.attemptAuthentication(request, response);
	}
	
	// attemptAuthentication 실행 후 인증이 정상적으로 되었으면. successfulAuthentication 함수가 실행된다.
	// 이 함수에서 JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response해주면 된다.
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		System.out.println("successfulAuthentication 실행됨 : 인증이 완료됨.");
		PrincipalDetails principalDetails = (PrincipalDetails)authResult.getPrincipal();
		
		// 빌더패턴
		// RSA 방식은 아니고 Hash암호방식
		String jwtToken = JWT.create()
				.withSubject("cos토큰")		//토큰이름
				.withExpiresAt(new Date(System.currentTimeMillis() + (60000*10)))		//만료시간  System.currentTimeMillis() : 현재시간   +    10분
				.withClaim("id", principalDetails.getUser().getId())
				.withClaim("username", principalDetails.getUser().getUsername())		//withClaim  >> 비공개 클레임  내가 넣고 싶은 값넣으면 됨.
				.sign(Algorithm.HMAC512("cos"));		// 내 서버만 아는 고유값
		
		response.addHeader("Authorization", "Bearer "+jwtToken);  // "Bearer " 공백!   사용자에게 응답 : response
	}
	
	
}
