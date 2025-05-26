package se.iths.webservices.clientservice.controller;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;

@Controller
public class QuotesController {

    private final WebClient webClient;

    public QuotesController() {
        this.webClient = WebClient.builder()
                .baseUrl("http://localhost:8080")  // to gateway
                .build();
    }

    @GetMapping("/quotes")
    public String quotes() {
        return "quotes";
    }

    @GetMapping("/quotes/random")
    public String jokes(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient client,
                        Model model) {

        var randomQuote = webClient.get()
                .uri("/quotes/random")
                .headers(h -> h.setBearerAuth(client.getAccessToken().getTokenValue()))
                .retrieve()
                .bodyToMono(String.class)
                .block(Duration.ofSeconds(5));

        model.addAttribute("randomQuote", randomQuote);

        return "quotes";
    }
}
