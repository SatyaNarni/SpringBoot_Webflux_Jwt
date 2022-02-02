package com.microservices.estockmarket.cloudgateway;

import org.springframework.security.core.AuthenticationException;

@SuppressWarnings("serial")
public class InvalidBearerToken extends AuthenticationException{

	public InvalidBearerToken(String msg) {
		super(msg);
		// TODO Auto-generated constructor stub
	}

}
