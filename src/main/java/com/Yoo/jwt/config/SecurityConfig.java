package com.Yoo.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

import com.Yoo.jwt.config.jwt.JwtAuthenticationFilter;
import com.Yoo.jwt.config.jwt.JwtAuthorizationFilter;
import com.Yoo.jwt.filter.MyFilter3;
import com.Yoo.jwt.repository.UserRepository;

import lombok.RequiredArgsConstructor;


@Configuration	// IoC 할수 있게 만들어주고
@EnableWebSecurity	//이 시큐리티를 활성화
@RequiredArgsConstructor //DI 하는 방법중 하나?
public class SecurityConfig extends WebSecurityConfigurerAdapter{

	private final CorsFilter corsFilter; //DI 하는 방법중 하나?
	private final UserRepository userRepository;
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		//http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class);
		http.csrf().disable();
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) 	// 세션을 사용하지 않겠다.
		.and()
		.addFilter(corsFilter)		// 모든 요청은 이 필터를 통하게 된다.	이렇게 되면 내 서버는 cors 정책에서 벗어날 수 있다. 크로스오리진요청이 와도 다 허용이 된다.  @CrossOrigin(인증X때), 시큐리티 필터에 등록 인증(O을때)
		.formLogin().disable()		//formlogin 안쓸거야
		.httpBasic().disable()
		.addFilter(new JwtAuthenticationFilter(authenticationManager()))	//꼭 넘겨줘야하는 파라미터 : AuthenticationManager, authenticationManager()는 WebSecurityConfigurerAdapter가 들고 있다.
		.addFilter(new JwtAuthorizationFilter(authenticationManager(),userRepository))
		.authorizeRequests()
		.antMatchers("/api/v1/user/**")
		.access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
		.antMatchers("/api/v1/manager/**")
		.access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
		.antMatchers("/api/v1/admin/**")
		.access("hasRole('ROLE_ADMIN')")
		.anyRequest().permitAll();
		
	}
}
