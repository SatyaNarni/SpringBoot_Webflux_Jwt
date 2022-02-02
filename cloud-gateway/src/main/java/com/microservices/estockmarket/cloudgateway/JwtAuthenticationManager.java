package com.microservices.estockmarket.cloudgateway;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import reactor.core.publisher.Mono;

@Component
public class JwtAuthenticationManager implements ReactiveAuthenticationManager {
	
	@Autowired
	private JwtSupport jwtSupport;
	
	@Autowired
	private ReactiveUserDetailsService users;
	
	@Override
	public Mono<Authentication> authenticate(Authentication authentication) {
		return Mono.justOrEmpty(authentication)
				.filter(auth -> auth instanceof BearerToken)
				.cast(BearerToken.class)
				.flatMap(jwt -> Mono.just(validate(jwt)))
				.onErrorMap(error -> new InvalidBearerToken(error.getMessage()));
	}
	
	
	private Authentication validate(BearerToken token) {
		String username = jwtSupport.getUserName(token);
		Mono<UserDetails> userDetails = users.findByUsername(username);
		if(jwtSupport.isValid(token, userDetails.block())) {
			return new UsernamePasswordAuthenticationToken(token.getPrincipal(),token.getCredentials(),token.getAuthorities());
		}
		 throw new IllegalArgumentException("Token is not valid.");
	}
}
