package se.iths.webservices.clientservice.controller;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;

@Controller
public class JokesController {

    private final WebClient webClient;

    public JokesController() {
        this.webClient = WebClient.builder()
                .baseUrl("http://localhost:8080")  // to gateway
                .build();
    }

    @GetMapping("/jokes")
    public String jokes() {
        return "jokes";
    }

    @GetMapping("/jokes/random")
    public String jokes(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient client,
                        Model model) {

        var randomJoke = webClient.get()
                .uri("/jokes/random")
                .headers(h -> h.setBearerAuth(client.getAccessToken().getTokenValue()))
                .retrieve()
                .bodyToMono(String.class)
                .block(Duration.ofSeconds(5));

        model.addAttribute("randomJoke", randomJoke);

        return "jokes";
    }
}
