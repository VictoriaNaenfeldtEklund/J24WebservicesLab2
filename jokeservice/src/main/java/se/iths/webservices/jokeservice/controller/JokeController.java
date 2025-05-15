package se.iths.webservices.jokeservice.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JokeController {

    @GetMapping("/jokes/random")
    public String getRandomJoke() {
        return "Hello from jokeService!";
    }
}
