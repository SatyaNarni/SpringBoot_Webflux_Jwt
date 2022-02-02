package com.microservices.estockmarket.cloudgateway;

public class Jwt {
	private String token;

	public Jwt() {
	
	}

	public Jwt(String token) {
		this.token = token;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	@Override
	public String toString() {
		return "Jwt [token=" + token + "]";
	}
		

}
