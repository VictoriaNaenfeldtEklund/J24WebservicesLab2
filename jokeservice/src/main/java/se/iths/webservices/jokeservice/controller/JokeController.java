package se.iths.webservices.jokeservice.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

@RestController
@RequestMapping("/jokes")
public class JokeController {

    private final List<String> jokes;

    public JokeController() {
        jokes = List.of(
                "Why don’t skeletons fight each other? They don’t have the guts.",
                "What do you call fake spaghetti? An impasta!",
                "Why did the scarecrow win an award? Because he was outstanding in his field!",
                "Parallel lines have so much in common. It’s a shame they’ll never meet.",
                "What’s orange and sounds like a parrot? A carrot.",
                "Why was the math book sad? Because it had too many problems.",
                "Why do cows have hooves instead of feet? Because they lactose."
        );
    }

    @GetMapping("/random")
    public String randomJoke() {
        return jokes.get(ThreadLocalRandom.current().nextInt(jokes.size()));
    }
}
