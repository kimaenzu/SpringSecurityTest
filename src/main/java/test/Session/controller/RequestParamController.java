package test.Session.controller;

import io.jsonwebtoken.Header;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import test.Session.security.dto.TokenDto;
import test.Session.security.service.MemService;
import test.Session.security.service.UserDS;

import java.io.IOException;

@Slf4j
@Controller
public class RequestParamController {
    /*
    private final UserDS userDS;
    public RequestParamController(UserDS userDS){
        this.userDS = userDS;
    }
    @RequestMapping("/sample/all")
    public String requestParamV1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        System.out.println("/sample/all ....");
//        MemService.login();
        //TokenDto token = userDS.login();
//        response.addHeader("token", token.getAccessToken());
        return "sample/all";
    }

     */
}
