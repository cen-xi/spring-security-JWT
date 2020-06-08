package com.example.securityjwt5605.controller;


import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class HHController {

    //开启跨域
    // [普通跨域]
    //@CrossOrigin
    //[spring security 跨域]
    @CrossOrigin(allowCredentials = "true", allowedHeaders = "*")
    @RequestMapping("/hello")
    public Map<String, Object> hello() {
        Map<String, Object> map = new HashMap<>();
        map.put("data", "hello");
        return map;
    }

    //开启跨域
    // [普通跨域]
    //@CrossOrigin
    //[spring security 跨域]
    @CrossOrigin(allowCredentials = "true", allowedHeaders = "*")
    @RequestMapping("/admin")
    public Map<String, Object> admin() {
        Map<String, Object> map = new HashMap<>();
        map.put("data", "i am admin");
        return map;
    }


}
