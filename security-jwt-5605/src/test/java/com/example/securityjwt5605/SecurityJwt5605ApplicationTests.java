package com.example.securityjwt5605;


import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;


class SecurityJwt5605ApplicationTests {

    @Test
    void contextLoads() {
        System.out.println((new BCryptPasswordEncoder()).encode("11"));
    //$2a$10$Qghi7vHdyQJHYlAO.FCo/u3gCbqwWBVaSHjIF0Vci.C5.1l71SExq
        //$2a$10$ywq3gn6E15tnY3URptsIz.zn/fznWGqc2VhO4zphS/sIbWZJtLCVK
    }

}
