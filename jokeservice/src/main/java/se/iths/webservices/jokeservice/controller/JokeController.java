package se.iths.webservices.jokeservice.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/jokes")
public class JokeController {

//    @GetMapping("/secure")
//    public String secure() {
//        return "Hello from SECURE jokeService!";
//    }
//
    @GetMapping("/public")
    public String getpublic() {
        return "Hello from PUBLIC jokeService!";
    }

    @GetMapping("/random")
    public String getRandom() {
        return "Hello from RANDOM jokeService!";
    }
}
