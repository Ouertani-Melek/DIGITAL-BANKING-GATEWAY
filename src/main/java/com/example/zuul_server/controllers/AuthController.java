package com.example.zuul_server.controllers;

import com.example.zuul_server.config.JwtTokenProvider;
import com.example.zuul_server.models.User;
import com.example.zuul_server.repositories.RoleRepository;
import com.example.zuul_server.repositories.UserRepository;
import com.example.zuul_server.services.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;

import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import static org.springframework.http.ResponseEntity.ok;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

	@Autowired
    AuthenticationManager authenticationManager;

	@Autowired
	JwtTokenProvider jwtTokenProvider;

	@Autowired
	UserRepository users;

	@Autowired
	private RoleRepository roles;

	@Autowired
	private CustomUserDetailsService userService;


	@PostMapping("/login")
	public ResponseEntity login(@RequestBody AuthBody data) {
		try {
			String username = data.getEmail();
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, data.getPassword()));
			String token = jwtTokenProvider.createToken(username, this.users.findByEmail(username).getRoles());
			Map<Object, Object> model = new HashMap<>();
			model.put("username", username);
			model.put("token", token);
			model.put("_id",this.users.findByEmail(username).getId());
			model.put("firstName",this.users.findByEmail(username).getFirstName());
			model.put("lastName",this.users.findByEmail(username).getLastName());
			model.put("createdDate",new Date());
			model.put("roles",this.users.findByEmail(username).getRoles());
			return ok(model);
		} catch (AuthenticationException e) {
			throw new BadCredentialsException("Invalid email/password supplied");
		}
	}

	@SuppressWarnings("rawtypes")
	@PostMapping("/register")
	public ResponseEntity register(@RequestBody User user) {
		User userExists = userService.findUserByEmail(user.getEmail());
		if (userExists != null) {
			return new ResponseEntity<String>("Vous Avez déja un compte", HttpStatus.FOUND);
		}
		user.setRoles(new HashSet<>());
		user.getRoles().add(roles.findByRole("USER"));
		userService.saveUser(user);
		Map<Object, Object> model = new HashMap<>();
		model.put("message", "User registered successfully");
		return ok(model);
	}
}
