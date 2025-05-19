package se.iths.webservices.authservice.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    @GetMapping("/secure")
    public String secure() {
        return "Hello from secure!";
    }

    @GetMapping("/open")
    public String open() {
        return "Hello from open!";
    }
}
