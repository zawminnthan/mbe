package com.ithub.mbe;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

@RestController
public class QRController {

    @GetMapping("/purchaseQR")
    private String getAllTweets() {

        return "";
    }
}
