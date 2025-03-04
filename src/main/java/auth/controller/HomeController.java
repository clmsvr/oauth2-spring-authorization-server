package auth.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

	@GetMapping("/login")
	String login() {
		return "auth/login";
	}
	
	@GetMapping("/")
	String home() {
		return "auth/home";
	}
}
