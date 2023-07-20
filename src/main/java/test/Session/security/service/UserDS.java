package test.Session.security.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import test.Session.entity.Mem;
import test.Session.repository.MemRepository;
import test.Session.security.dto.AuthMemDTO;

import java.util.Optional;
import java.util.stream.Collectors;

@Log4j2
@Service
@RequiredArgsConstructor
public class UserDS implements UserDetailsService {

    private final MemRepository memRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("UserDS loadUserByUsername : " + username);
        Optional<Mem> result = memRepository.findByEmail(username, false);
        log.info("result!  : " + result);
        if (!result.isPresent()) {
            log.info("value != null : true");
            throw new UsernameNotFoundException("Check Email of Social");
        } else {
            log.info("value != null : false");
        }

        log.info("here!");
        Mem mem = result.get();
        log.info("mem!  : " + mem);
        log.info("----------------");
        log.info(mem);

        AuthMemDTO authMemDTO = new AuthMemDTO(
                mem.getEmail(),
                mem.getPassword(),
                mem.isFromSocial(),
                mem.getRoleSet().stream()
                        .map(role -> new SimpleGrantedAuthority("ROLE_"+role.name())).collect(Collectors.toSet()));

        authMemDTO.setName(mem.getName());
        authMemDTO.setFromSocial(mem.isFromSocial());
        return authMemDTO;
    }

}
