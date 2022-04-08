package ru.forsh.spring_boot_oauth2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

/*
Spring Boot attaches special meaning to a WebSecurityConfigurerAdapter on the class
annotated with @SpringBootApplication: It uses it to configure the security
filter chain that carries the OAuth 2.0 authentication processor.
 */

@SpringBootApplication
@RestController
public class SocialApplication extends WebSecurityConfigurerAdapter {



	@GetMapping("/user")
	public Map<String, Object> user(@AuthenticationPrincipal OAuth2User principal){
		return Collections.singletonMap("name", principal.getAttribute("name"));
	}


	public static void main(String[] args) {
		SpringApplication.run(SocialApplication.class, args);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		//@formatter:off
		http
				.authorizeRequests(a -> a.antMatchers("/", "/error", "/webjars/**").permitAll())
						.exceptionHandling(e -> e.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
								)
				.logout(l->l.logoutSuccessUrl("/").permitAll())
				.csrf(c -> c.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
				.oauth2Login();
		// @formatter:on
	}

}
