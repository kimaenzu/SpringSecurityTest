package test.Session.controller;

import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import test.Session.security.dto.AuthMemDTO;

@Controller
@Log4j2
@RequestMapping("/sample")
public class SampleController {
    /*
    사용자 권한에 따른 접근 경로 지정
    모든 사용자 허용 : /all
    로그인한 사용자 허용 : /member
    관리자 권한 사용자만 허용 : /admin
     */
    @GetMapping("/all")
    public void exAll(){
        log.info("exAll............");
    }

    @GetMapping("/member")
    public void exMember(@AuthenticationPrincipal AuthMemDTO authMemDTO){
        log.info("exMember............");
        // 로그인된 사용자 정보 확인 @AuthenticationPrincipal : 별도의 캐스팅 작업 없이 실제 DTO 타입 사용 가능.
        log.info("authMemDTO : " + authMemDTO);
    }

    @GetMapping("/admin")
    public void exAdmin(){
        log.info("exAdmin............");
    }
}
