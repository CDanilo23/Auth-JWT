package com.bolsadeideas.springboot.app.auth.filter;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.bolsadeideas.springboot.app.models.entity.Usuario;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter{
	
	private AuthenticationManager authenticationManager; 	
	
	public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
		setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/api/login", "POST"));
	}



	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

		String username = obtainUsername(request);
		String password = obtainPassword(request);

		if(username!=null && password!=null) {
			logger.info("Username from request parameter (form-data): "+ username);
			logger.info("Password from request parameter (form-data): "+ password);
		}else {
			Usuario user = null;
			try {
			   user = new ObjectMapper().readValue(request.getInputStream(),Usuario.class);
			   username = user.getUsername();
			   password = user.getPassword();
			   
			   logger.info("Username from request parameter (raw): "+ username);
			   logger.info("Password from request parameter (raw): "+ password);
			   
			} catch (JsonParseException e) {
				 logger.info(e.getMessage());
			} catch (JsonMappingException e) {
				 logger.info(e.getMessage());
			} catch (IOException e) {
				 logger.info(e.getMessage());
			}
			
		}
		
		username = username.trim();

		UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);

		return authenticationManager.authenticate(authToken);
	}
	
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult)
			throws IOException, ServletException {
		
		String username = ((User) authResult.getPrincipal()).getUsername();

		String token = Jwts.builder().
				setSubject(username).
				signWith(SignatureAlgorithm.HS512, "clave".getBytes())
				.setIssuedAt(new Date(System.currentTimeMillis() + 14000000L))
				.compact();
		
		response.addHeader("Authorization", "Bearer "+token);
		
		Map<String, Object> body = new HashMap<String,Object>();
		body.put("token", token);
		body.put("user", (User) authResult.getPrincipal());
		body.put("mensaje", String.format("Hola %s, has iniciado sesión con exito!!", username));
		
		response.getWriter().write(new ObjectMapper().writeValueAsString(body));
		response.setStatus(200);
		response.setContentType("application/json");

	}
	
}
