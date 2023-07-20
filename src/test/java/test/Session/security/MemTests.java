package test.Session.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import test.Session.entity.Mem;
import test.Session.entity.MemRole;
import test.Session.repository.MemRepository;

import java.util.Optional;
import java.util.stream.IntStream;

@SpringBootTest
public class MemTests {
    @Autowired
    private MemRepository repository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    public void insertDummies(){
        IntStream.rangeClosed(1, 100).forEach(i -> {
            Mem mem = Mem.builder().email("user"+i+"@test.com")
                    .name("name"+i).fromSocial(false)
                    .password(passwordEncoder.encode("1111")).build();
            // default role
            mem.addMemRole(MemRole.USER);

            if(i>80){
                mem.addMemRole(MemRole.MEMBER);
            }
            if(i>90){
                mem.addMemRole(MemRole.ADMIN);
            }

            repository.save(mem);
        });
    }

    @Test
    public void testRead(){
        Optional<Mem> result = repository.findByEmail("user95@test.com", false);
        Mem mem = result.get();
        System.out.println(mem);
    }
}
