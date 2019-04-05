package com.gnu.ssl.server.test.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SSLController {
	
	@RequestMapping("/endpoint")
	public @ResponseBody boolean endpoint() {
		return true;
	}
}
