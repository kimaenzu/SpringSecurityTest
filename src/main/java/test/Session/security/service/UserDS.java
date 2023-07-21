package test.Session.security.service;

import jakarta.servlet.http.Cookie;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import test.Session.entity.Mem;
import test.Session.jwt.JwtTokenProvider;
import test.Session.repository.MemRepository;
import test.Session.security.dto.AuthMemDTO;
import test.Session.security.dto.TokenDto;

import java.util.Optional;
import java.util.stream.Collectors;

@Log4j2
@Service
@RequiredArgsConstructor
public class UserDS implements UserDetailsService {

    private final MemRepository memRepository;
    private final MemService memService;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final JwtTokenProvider jwtTokenProvider;
    private static Mem mem;
    static PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<Mem> result = memRepository.findByEmail(username, false);
        if (!result.isPresent()) {
            throw new UsernameNotFoundException("Check Email of Social");
        }

        // 여기까지 오면 인증이 완료된 상태

        Mem mem = result.get();
        log.info(mem);

        TokenDto token = memService.login(mem.getName(), mem.getPassword());
        AuthMemDTO authMemDTO = new AuthMemDTO(
                mem.getEmail(),
                passwordEncoder.encode(mem.getPassword()),
                mem.isFromSocial(),
                mem.getRoleSet().stream()
                        .map(role -> new SimpleGrantedAuthority("ROLE_"+role.name())).collect(Collectors.toSet()));

        authMemDTO.setName(mem.getName());
        authMemDTO.setFromSocial(mem.isFromSocial());
        return authMemDTO;

    }


    // 3. 인증 정보를 기반으로 JWT 토큰 생성
    @Transactional
    public TokenDto login() {
        // 1. Login ID/PW 를 기반으로 Authentication 객체 생성
        // 이때 authentication 는 인증 여부를 확인하는 authenticated 값이 false
        //UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(memberId, password);

        // 2. 실제 검증 (사용자 비밀번호 체크)이 이루어지는 부분
        // authenticate 매서드가 실행될 때 CustomUserDetailsService 에서 만든 loadUserByUsername 메서드가 실행
        //Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

        // 3. 인증 정보를 기반으로 JWT 토큰 생성
        //TokenDto tokenDto = jwtTokenProvider.generateToken(authentication);
        TokenDto tokenDto = memService.login(mem.getName(), mem.getPassword());
        return tokenDto;
    }
}
