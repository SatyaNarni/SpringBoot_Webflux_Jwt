package com.microservices.estockmarket.cloudgateway;

import java.security.Principal;
//import java.util.stream.IntStream;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import reactor.core.publisher.Mono;


@RestController
public class Controller {
	@Autowired
	private PasswordEncoder encoder;
	
	@Autowired
	private ReactiveUserDetailsService users;
	
	@Autowired
	private JwtSupport jwtSupport;
	
	
	@GetMapping("/home")
	public String home(@AuthenticationPrincipal Principal principal) {
		return "Welcome...! "+ principal.getName();
	}
	
	@PostMapping("/login")
	public Jwt login(@RequestBody AuthRequest req) {
		System.out.println("HELLOOO... " + req.getUsername() + req.getPassword());
		
		Mono<UserDetails> userDetails = users.findByUsername(req.getUsername());
		System.out.println(userDetails+" heloo");
		
		if(encoder.matches(req.getPassword(), userDetails.block().getPassword())) {
			return new Jwt(jwtSupport.generate(req.getUsername()).getValue());
		}
		throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);	
	}
	
	
}
