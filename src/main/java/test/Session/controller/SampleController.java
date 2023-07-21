package test.Session.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import test.Session.security.dto.AuthMemDTO;
import test.Session.security.dto.TokenDto;
import test.Session.security.service.MemService;

import java.io.IOException;
import java.util.Map;

@Controller
@Log4j2
@RequiredArgsConstructor
@RequestMapping("/sample")
public class SampleController {
    private final MemService memService;
    private SecurityContextRepository securityContextRepository =
            new HttpSessionSecurityContextRepository();
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    /*
    사용자 권한에 따른 접근 경로 지정
    모든 사용자 허용 : /all
    로그인한 사용자 허용 : /member
    관리자 권한 사용자만 허용 : /admin
     */



    @RequestMapping("/all")
    public String exAll(){
        log.info("exAll............");
        return "sample/all";
    }


    @RequestMapping("/member")
    public String exMember(@AuthenticationPrincipal AuthMemDTO authMemDTO){
        log.info("exMember............");
        // 로그인된 사용자 정보 확인 @AuthenticationPrincipal : 별도의 캐스팅 작업 없이 실제 DTO 타입 사용 가능.
        log.info("authMemDTO : " + authMemDTO);
        return "sample/member";
    }

    @RequestMapping("/admin")
    public String exAdmin(){
        log.info("exAdmin............");
        return "sample/admin";
    }

    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public String exLogin(){
        log.info("exLogin............");
        return "sample/login";
    }
    /*
    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public ResponseEntity<TokenDto> loginSuccess(HttpServletRequest request) {
        TokenDto token = memService.login((String) request.getAttribute("username"), (String) request.getAttribute("password"));
        System.out.println("/login : token" + token);
        return ResponseEntity.ok(token);
    }*/
    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public String loginSuccess(HttpServletRequest request, HttpServletResponse response) {
        System.out.println("login!!");
        String username = request.getParameter("username");
        System.out.println("username done : " + username);
        String password = request.getParameter("password");
        System.out.println("password done : " + password);

        TokenDto token = memService.login(username, password);
        System.out.println("token done");

        System.out.println("/login : token" + token);
        response.setHeader("token", token.toString());
        return "sample/member";
    }
    /*
    @GetMapping("/all")
    public String exAll(){
        log.info("exAll............");
        return "all";
    }
    @GetMapping("/member")
    public String exMember(@AuthenticationPrincipal AuthMemDTO authMemDTO){
        log.info("exMember............");
        // 로그인된 사용자 정보 확인 @AuthenticationPrincipal : 별도의 캐스팅 작업 없이 실제 DTO 타입 사용 가능.
        log.info("authMemDTO : " + authMemDTO);
        return "member";
    }

    @GetMapping("/admin")
    public void exAdmin(){
        log.info("exAdmin............");
    }

    @PostMapping("/login")
    public ResponseEntity<TokenDto> loginSuccess(@RequestBody Map<String, String> loginForm) {
        System.out.println(loginForm);
        TokenDto token = memService.login(loginForm.get("username"), loginForm.get("password"));
        System.out.println("/login : token" + token);
        return ResponseEntity.ok(token);
    }

     */
}
