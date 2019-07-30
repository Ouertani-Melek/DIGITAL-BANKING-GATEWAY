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
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.AuthenticationException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.springframework.http.ResponseEntity.ok;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private static final String TYPEMESSAGE = "message";
    Logger logger = LoggerFactory.getLogger(AuthController.class);

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
    public ResponseEntity login(@RequestBody AuthBody data){
        try {
            String username = data.getEmail();
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, data.getPassword()));
            User user = this.users.findByEmail(username);
            if (!user.isActivated()) {
                return new ResponseEntity(HttpStatus.NOT_ACCEPTABLE);
            }
            if (!user.isEnabled()) {
                return new ResponseEntity(HttpStatus.FORBIDDEN);
            }
            String token = jwtTokenProvider.createToken(username, this.users.findByEmail(username).getRoles());
            Map<Object, Object> model = new HashMap<>();
            model.put("email", username);
            model.put("token", token);
            model.put("_id", user.getId());
            model.put("firstName", user.getFirstName());
            model.put("lastName", user.getLastName());
            model.put("createdDate", user.getCreatedDate());
            model.put("roles", user.getRoles());
            model.put("activated", user.isActivated());
            model.put("enabled", user.isEnabled());
            model.put("password", user.getPassword());
            return ok(model);
        } catch (AuthenticationException e) {
            throw e;
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
        //sending confirmation  mail
        ConfirmationToken confirmationToken = new ConfirmationToken(user);
        confirmationTokenRepository.save(confirmationToken);
        SimpleMailMessage mailMessage = new SimpleMailMessage();
        mailMessage.setTo(user.getEmail());
        mailMessage.setFrom("biat.stage@gmail.com");
        mailMessage.setText("To confirm your account please click here : " + "http://localhost:8084/api/auth/confirm-account/" + confirmationToken.getConfirmationToken());
        emailSenderService.sendEmail(mailMessage);
        Map<Object, Object> model = new HashMap<>();
        model.put(TYPEMESSAGE, "User registered successfully");
        return ok(model);
    }


    @RequestMapping(value = "/confirm-account/{token}", method = {RequestMethod.GET})
    public String confirmUserAccount(@PathVariable("token") String confirmationToken) {
        ConfirmationToken token = confirmationTokenRepository.findByConfirmationToken(confirmationToken);
        Map<Object, Object> model = new HashMap<>();
        if (token != null) {
            User user = users.findByEmail(token.getUser().getEmail());
            user.setId(token.getUser().getId());
            user.setActivated(true);
            users.save(user);
            return htmlContent("Vous pouvez vous connectez avec votre compte désormais ...");
        } else {
            return htmlContent("Token de confirmation est invalide");
        }
    }

    private String htmlContent(String content){

        return  "<html>\n" +
                "  <head>\n" +
                "   <link rel=\"stylesheet\" href=\"https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css\">\n" +
                "   <style>\n" +
                "      a,a:focus,a:hover {\n" +
                "        color: #fff;\n" +
                "      }\n" +
                "      .btn-secondary,\n" +
                "      .btn-secondary:hover,\n" +
                "      .btn-secondary:focus {\n" +
                "        color: #333;\n" +
                "        text-shadow: none; /* Prevent inheritance from `body` */\n" +
                "        background-color: #fff;\n" +
                "        border: .05rem solid #fff;\n" +
                "      }\n" +
                "      body {\n" +
                "        display: -ms-flexbox;\n" +
                "        display: flex;\n" +
                "        color: #fff;\n" +
                "        text-shadow: 0 .05rem .1rem rgba(0, 0, 0, .5);\n" +
                "        box-shadow: inset 0 0 5rem rgba(0, 0, 0, .5);\n" +
                "        background-image: url('https://i.ibb.co/6Ff6yzQ/404.jpg');\n" +
                "        background-size: 100% 100%;\n" +
                "      }\n" +
                "      .cover-container {\n" +
                "        max-width: 42em;\n" +
                "      }\n" +
                "      .masthead {\n" +
                "        margin-bottom: 2rem;\n" +
                "      }\n" +
                "      .masthead-brand {\n" +
                "        margin-bottom: 0;\n" +
                "      }\n" +
                "      .nav-masthead .nav-link {\n" +
                "        padding: .25rem 0;\n" +
                "        font-weight: 700;\n" +
                "        color: rgba(255, 255, 255, .5);\n" +
                "        background-color: transparent;\n" +
                "        border-bottom: .25rem solid transparent;\n" +
                "      }\n" +
                "      .nav-masthead .nav-link:hover,\n" +
                "      .nav-masthead .nav-link:focus {\n" +
                "        border-bottom-color: rgba(255, 255, 255, .25);\n" +
                "      }\n" +
                "      .nav-masthead .nav-link + .nav-link {\n" +
                "        margin-left: 1rem;\n" +
                "      }\n" +
                "      .nav-masthead .active {\n" +
                "        color: #fff;\n" +
                "        border-bottom-color: #fff;\n" +
                "      }\n" +
                "      @media (min-width: 48em) {\n" +
                "        .masthead-brand {\n" +
                "          float: left;\n" +
                "        }\n" +
                "        .nav-masthead {\n" +
                "          float: right;\n" +
                "        }\n" +
                "      }\n" +
                "      .cover {\n" +
                "        padding: 0 1.5rem;\n" +
                "      }\n" +
                "      .cover .btn-lg {\n" +
                "        padding: .75rem 1.25rem;\n" +
                "        font-weight: 700;\n" +
                "      }\n" +
                "      .mastfoot {\n" +
                "        color: rgba(255, 255, 255, .5);\n" +
                "      }\n" +
                "          </style>\n" +
                "  </head>\n" +
                "<body>\n" +
                "  <div class=\"cover-container d-flex w-100 h-100 p-3 mx-auto flex-column\">\n" +
                "    <header class=\"masthead mb-auto\">\n" +
                "      <div class=\"inner\">\n" +
                "        <img src=\"https://i.ibb.co/D9tVXrj/biat.png\" class=\"img-fluid masthead-brand\" style=\" width:50px;height: 50px\"/>\n" +
                "  \n" +
                "      </div>\n" +
                "    </header>\n" +
                "  \n" +
                "    <main role=\"main\" class=\"inner cover\" style=\"margin-top : 150px\">\n" +
                "      <h1 class=\"cover-heading\">Validation de compte</h1>\n" +
                "      <p class=\"lead\">"+content+"</p>\n" +
                "      <p class=\"lead\" style=\"margin-top : 150px\">\n" +
                "          <a href=\"http://localhost:4200/login\" class=\"btn btn-lg btn-secondary\">Page Accueil</a>\n" +
                "      </p>\n" +
                "    </main>\n" +
                "  \n" +
                "    <footer class=\"mastfoot mt-auto\">\n" +
                "      <div class=\"inner\">\n" +
                "  \n" +
                "      </div>\n" +
                "    </footer>\n" +
                "  </div>\n" +
                "  </body>\n" +
                "</html>";
    }


}
