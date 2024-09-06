package net.samitkumar.spring_security_websocket;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.handler.annotation.MessageExceptionHandler;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.messaging.simp.annotation.SendToUser;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;
import org.springframework.web.util.HtmlUtils;

import java.security.Principal;
import java.util.Collection;
import java.util.List;

@SpringBootApplication
public class SpringSecurityWebsocketApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityWebsocketApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}


@Service
@RequiredArgsConstructor
class Db {
	final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

	final List<User> users = List.of(
			new User("user", passwordEncoder.encode("password"), List.of("USER"), false),
			new User("admin", passwordEncoder.encode("password"), List.of("ADMIN"), false),
			new User("samit", passwordEncoder.encode("password"), List.of("USER"), false),
			new User("Raj", passwordEncoder.encode("password"), List.of("USER"), false)
	);

	public User findByUsername(String username) {
		return users.stream().filter(u -> u.username().equals(username)).findFirst().orElseThrow();
	}

	public List<User> findAll() {
		return users.stream().map(u -> new User(u.username(), null, u.authorities(), u.status())).toList();
	}
	
}

@Service
@RequiredArgsConstructor
class UserDetailsServiceImpl implements UserDetailsService {
	private final Db db;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		return db.findByUsername(username);
	}
}

@RestController
@RequiredArgsConstructor
@CrossOrigin(originPatterns = "*")
class Endpoints {
	final Db db;

	@GetMapping("/me")
	UserDetails me(Authentication authentication) {
		//SecurityContextHolder.getContext().getAuthentication();
		return (UserDetails) authentication.getPrincipal();
	}

	@GetMapping("/users")
	List<User> users() {
		return db.findAll();
	}

}

@EnableWebSecurity
@Configuration
class SecurityConfig {
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
				.authorizeHttpRequests((authorize) -> authorize
						.anyRequest().authenticated()
				)
				.httpBasic(Customizer.withDefaults())
				.formLogin(Customizer.withDefaults());

		return http.build();
	}

}

record User(String username, String password, List<String> authorities, boolean status) implements UserDetails {
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities.stream().map(a -> (GrantedAuthority) () -> a).toList();
	}

	@Override
	public String getPassword() {
		return password();
	}

	@Override
	public String getUsername() {
		return username();
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}
}

record Message(String from, String to, String message) {}

@Configuration
@EnableWebSocketMessageBroker
class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

	@Override
	public void registerStompEndpoints(StompEndpointRegistry registry) {
		registry.addEndpoint("/ws").setAllowedOriginPatterns("*").withSockJS();
	}

	@Override
	public void configureMessageBroker(MessageBrokerRegistry config) {
		config.setApplicationDestinationPrefixes("/app");
		config.enableSimpleBroker("/topic", "/queue");
		config.setUserDestinationPrefix("/user");
	}
}

@Controller
@Slf4j
@RequiredArgsConstructor
class StompEndpoints {
	final SimpMessagingTemplate simpMessagingTemplate;

	@MessageMapping("/message/public")
	@SendTo("/topic/public")
	Message publicMessage(@Payload Message message, Principal principal) {
		log.info("Received public message {}", message);
		return new Message(principal.getName(), message.to(), HtmlUtils.htmlEscape(message.message()));
	}

	@MessageMapping("/message/private")
	@SendToUser("/queue/private") //sent to self
	Message privateMessage(@Payload Message message, Principal principal) {
		log.info("Received private message {}", message);
		var messageToSent = new Message(principal.getName(), message.to(), HtmlUtils.htmlEscape(message.message()));
		//sent to target user
		simpMessagingTemplate.convertAndSendToUser(message.to(), "/queue/private", messageToSent);
		return messageToSent;
	}

	@MessageExceptionHandler
	public String handleException(Exception exception) {
		log.error("Exception in websocket", exception);
		return exception.getMessage();
	}
}