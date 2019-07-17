package com.example.zuul_server.controllers;

import com.example.zuul_server.config.JwtTokenProvider;
import com.example.zuul_server.models.ConfirmationToken;
import com.example.zuul_server.models.User;
import com.example.zuul_server.repositories.ConfirmationTokenRepository;
import com.example.zuul_server.repositories.RoleRepository;
import com.example.zuul_server.repositories.UserRepository;
import com.example.zuul_server.services.CustomUserDetailsService;
import com.example.zuul_server.services.EmailSenderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.security.authentication.AuthenticationManager;
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
	private ConfirmationTokenRepository confirmationTokenRepository;

	@Autowired
    AuthenticationManager authenticationManager;

	@Autowired
	JwtTokenProvider jwtTokenProvider;

	@Autowired
	UserRepository users;


	@Autowired
	private EmailSenderService emailSenderService;

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
			model.put("createdDate",this.users.findByEmail(username).getCreatedDate());
			model.put("roles",this.users.findByEmail(username).getRoles());
			return ok(model);
		} catch (AuthenticationException e) {
			return new ResponseEntity(HttpStatus.UNAUTHORIZED);
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

		ConfirmationToken confirmationToken = new ConfirmationToken(user);
		confirmationTokenRepository.save(confirmationToken);
		SimpleMailMessage mailMessage = new SimpleMailMessage();
		mailMessage.setTo(user.getEmail());
		mailMessage.setFrom("ouertanimelek@gmail.com");
		mailMessage.setText("To confirm your account please click here :" +"http://localhost:8084/api/auth/confirm-account/"+confirmationToken.getConfirmationToken());
        emailSenderService.sendEmail(mailMessage);


		Map<Object, Object> model = new HashMap<>();
		model.put("message", "User registered successfully");
		return ok(model);
	}


	@RequestMapping(value="/confirm-account/{token}", method= {RequestMethod.PUT,})
	public ResponseEntity confirmUserAccount(@PathVariable("token")String confirmationToken)
	{
		ConfirmationToken token = confirmationTokenRepository.findByConfirmationToken(confirmationToken);
		Map<Object, Object> model = new HashMap<>();

		if(token != null)
		{
			User user = users.findByEmail(token.getUser().getEmail());
			user.setId(token.getUser().getId());

			user.setActivated(true);
			users.save(user);

			model.put("message", "User registered successfully");

		}
		else
		{
			model.put("message","The link is invalid or broken!");

		}

		return ok(model);
	}


}
