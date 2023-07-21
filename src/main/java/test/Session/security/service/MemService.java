package test.Session.security.service;

//import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import test.Session.jwt.JwtTokenProvider;
import test.Session.repository.MemRepository;
import test.Session.security.dto.TokenDto;

import java.util.Collection;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class MemService {
    private final MemRepository memRepository;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final JwtTokenProvider jwtTokenProvider;


    /**
     * 1. 로그인 요청으로 들어온 ID, PWD 기반으로 Authentication 객체 생성
     * 2. authenticate() 메서드를 통해 요청된 Member에 대한 검증이 진행 => loadUserByUsername 메서드를 실행. 해당 메서드는 검증을 위한 유저 객체를 가져오는 부분으로써, 어떤 객체를 검증할 것인지에 대해 직접 구현
     * 3. 검증이 정상적으로 통과되었다면 인증된 Authentication객체를 기반으로 JWT 토큰을 생성
     */
    @Transactional
    public TokenDto login(String memberId, String password) {
        // 1. Login ID/PW 를 기반으로 Authentication 객체 생성
        // 이때 authentication 는 인증 여부를 확인하는 authenticated 값이 false
        System.out.println("memberId : "+memberId);
        System.out.println("### Create authenticationToken ###");
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(memberId, password);
        System.out.println("authenticationToken : "+ authenticationToken);
        System.out.println("### Create authentication ###");
        // 2. 실제 검증 (사용자 비밀번호 체크)이 이루어지는 부분
        // authenticate 매서드가 실행될 때 CustomUserDetailsService 에서 만든 loadUserByUsername 메서드가 실행
        System.out.println(authenticationManagerBuilder);
        System.out.println(authenticationManagerBuilder.getObject());
        try {
            System.out.println(authenticationManagerBuilder.getObject().authenticate(authenticationToken));
        } catch (AuthenticationException e) {
            System.out.println("trycatcherror");
            e.printStackTrace();
        }
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        System.out.println("authentication : "+ authentication);
        // 3. 인증 정보를 기반으로 JWT 토큰 생성
        System.out.println("### generateToken tokenDto ###");
        TokenDto tokenDto = jwtTokenProvider.generateToken(authentication);

        return tokenDto;
    }
}