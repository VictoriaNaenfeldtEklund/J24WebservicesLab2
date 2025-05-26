package se.iths.webservices.quoteservice.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

@RestController
@RequestMapping("/quotes")
public class QuoteController {

    private final List<String> quotes;

    public QuoteController() {
        quotes = List.of(
                "In the middle of every difficulty lies opportunity.\n- Albert Einstein",
                "Success is not final, failure is not fatal: It is the courage to continue that counts.\n- Winston Churchill",
                "Happiness depends upon ourselves.\n- Aristotle",
                "Do what you can, with what you have, where you are.\n- Theodore Roosevelt",
                "Life is what happens when you're busy making other plans.\n- John Lennon",
                "It does not matter how slowly you go as long as you do not stop.\n- Confucius",
                "Believe you can and you're halfway there.\n- Theodore Roosevelt"
        );
    }

    @GetMapping("/random")
    public String randomQuote() {
        return quotes.get(ThreadLocalRandom.current().nextInt(quotes.size()));
    }
}
