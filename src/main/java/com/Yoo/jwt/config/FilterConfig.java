package com.Yoo.jwt.config;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.Yoo.jwt.filter.MyFilter1;
import com.Yoo.jwt.filter.MyFilter2;

@Configuration	//IoC 등록
public class FilterConfig {

	@Bean
	public FilterRegistrationBean<MyFilter1> filter1(){
		FilterRegistrationBean<MyFilter1> bean = new FilterRegistrationBean<>(new MyFilter1());
		bean.addUrlPatterns("/*");
		bean.setOrder(1);	//낮은 번호가 필터중에서 가장 먼저 실행됨.
		return bean;
	}
	
	@Bean	//여러개 필터를 만들고 싶을때
	public FilterRegistrationBean<MyFilter2> filter2(){
		FilterRegistrationBean<MyFilter2> bean = new FilterRegistrationBean<>(new MyFilter2());
		bean.addUrlPatterns("/*");
		bean.setOrder(0);	//낮은 번호가 필터중에서 가장 먼저 실행됨.
		return bean;
	}
}
