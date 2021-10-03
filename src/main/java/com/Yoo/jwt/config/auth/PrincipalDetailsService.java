package com.Yoo.jwt.config.auth;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.Yoo.jwt.model.User;
import com.Yoo.jwt.repository.UserRepository;

import lombok.RequiredArgsConstructor;

// http://localhost:8080/login 요청이 올때 동작한다. 스프링시큐리티가 기본적으로 로그인 요청 주소가 /login 이다.
// 하지만 SecurityConfig 에서 formlogin을 disable 해서 동작을 안한다. 직접 이 UserDetailsService를 실행 시켜줄 filter가 필요
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {
	
	private final UserRepository  userRepository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		System.out.println("PrincipalDetailsService의 loadUserByUsername()");
		User userEntity = userRepository.findByUsername(username); 
		
		return new PrincipalDetails(userEntity);
	}

	
	
}
