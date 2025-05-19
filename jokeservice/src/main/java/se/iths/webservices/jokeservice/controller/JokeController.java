package se.iths.webservices.jokeservice.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JokeController {

    @GetMapping("/jokes/secure")
    public String getJokesSecure() {
        return "Hello from SECURE jokeService!";
    }

    @GetMapping("/jokes/public")
    public String getJokesPublic() {
        return "Hello from PUBLIC jokeService!";
    }

    @GetMapping("/jokes/random")
    public String getJokesRandom() {
        return "Hello from RANDOM jokeService!";
    }
}
