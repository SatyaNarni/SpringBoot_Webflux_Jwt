package com.microservices.estockmarket.cloudgateway;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

@SuppressWarnings("serial")
public class BearerToken extends AbstractAuthenticationToken {

	private String value;
	
	public BearerToken(Collection<? extends GrantedAuthority> authorities, String value) {
		super(authorities);
		this.setValue(value);
	}

	public BearerToken(Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		authorities = AuthorityUtils.NO_AUTHORITIES;
	}

	@Override
	public Object getCredentials() {
		// TODO Auto-generated method stub
		return value;
	}

	@Override
	public Object getPrincipal() {
		// TODO Auto-generated method stub
		return value;
	}

	public String getValue() {
		return value;
	}

	public void setValue(String value) {
		this.value = value;
	}

}
