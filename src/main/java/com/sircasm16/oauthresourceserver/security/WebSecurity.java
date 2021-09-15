package com.sircasm16.oauthresourceserver.security;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
		jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter());
		
		http.authorizeRequests()
			.antMatchers(HttpMethod.GET, "/users") 
			//.hasAuthority("SCOPE_profile")
			.hasRole("admin")
			.anyRequest().authenticated()
			.and()
			.oauth2ResourceServer()
			.jwt()
			.jwtAuthenticationConverter(jwtAuthenticationConverter);

	}
}
