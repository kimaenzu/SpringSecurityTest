package test.Session.repository;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import test.Session.entity.Mem;

import java.util.Optional;

public interface MemRepository extends JpaRepository<Mem, String> {

    @EntityGraph(attributePaths = {"roleSet"}, type=EntityGraph.EntityGraphType.LOAD)
    @Query("select m from Mem m where m.fromSocial = :social and m.email =:email")
    Optional<Mem> findByEmail(String email, boolean social);
}
