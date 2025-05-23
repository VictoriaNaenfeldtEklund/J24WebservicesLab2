package se.iths.webservices.gatewayservice.controller;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GatewayController {

    @GetMapping("/done")
    public String done(@RegisteredOAuth2AuthorizedClient("gateway-client") OAuth2AuthorizedClient client) {

        var accesstoken = client.getAccessToken();

        return "Gateway redirect endpoint!";
    }
}
