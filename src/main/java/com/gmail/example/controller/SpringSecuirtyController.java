package com.gmail.example.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/rest/auth")
public class SpringSecuirtyController {

	
	@GetMapping("/hello")
	public String sayHello() {
		return "Hello World";
	}
}
