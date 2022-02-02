//package com.microservices.estockmarket.cloudgateway.config;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.cloud.gateway.route.RouteLocator;
//import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//
//import com.microservices.estockmarket.cloudgateway.filter.JwtAuthenticationFilter;
//
//
//@Configuration
//public class GatewayConfig {
//
//	@Autowired
//	private JwtAuthenticationFilter filter;
//
//	@Bean
//	public RouteLocator routes(RouteLocatorBuilder builder) {
//		return builder.routes()
//				.route("auth-service", r -> r.path("/auth/**").filters(f -> f.filter(filter)).uri("lb://auth-service"))
//				.route("company-service", r -> r.path("/company/**").filters(f -> f.filter(filter)).uri("lb://company-service"))
//				.route("stock-service", r -> r.path("/stock/**").filters(f -> f.filter(filter)).uri("lb://stock-service")).build();
//	}
//
//}
