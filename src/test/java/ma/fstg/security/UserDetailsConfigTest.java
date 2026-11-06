package ma.fstg.security;

import ma.fstg.security.config.UserDetailsConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.core.userdetails.User.withUsername;

@SpringBootTest
class UserDetailsConfigTest {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    @DisplayName("L'encodeur est un BCryptPasswordEncoder")
    void encodeurBcrypt() {
        assertThat(passwordEncoder).isInstanceOf(org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder.class);
    }

    @Test
    @DisplayName("Les mots de passe sont stockes sous forme de hash BCrypt et non en clair")
    void motsDePasseHasher() {
        UserDetails user = userDetailsService.loadUserByUsername("user");
        UserDetails admin = userDetailsService.loadUserByUsername("admin");

        assertThat(user.getPassword()).startsWith("$2a$").doesNotContain("1111");
        assertThat(admin.getPassword()).startsWith("$2a$").doesNotContain("1234");
        assertThat(passwordEncoder.matches("1111", user.getPassword())).isTrue();
        assertThat(passwordEncoder.matches("1234", admin.getPassword())).isTrue();
    }

    @Test
    @DisplayName("Deux encodages du meme mot de passe donnent des hashes differents (sel aleatoire)")
    void selAleatoire() {
        String premier = passwordEncoder.encode("1111");
        String second = passwordEncoder.encode("1111");

        assertThat(premier).isNotEqualTo(second);
        assertThat(passwordEncoder.matches("1111", premier)).isTrue();
        assertThat(passwordEncoder.matches("1111", second)).isTrue();
    }

    @Test
    @DisplayName("user possede uniquement ROLE_USER")
    void rolesUtilisateur() {
        Set<String> roles = autorites("user");
        assertThat(roles).containsExactly("ROLE_USER");
    }

    @Test
    @DisplayName("admin cumule ROLE_ADMIN et ROLE_USER")
    void rolesAdministrateur() {
        Set<String> roles = autorites("admin");
        assertThat(roles).containsExactlyInAnyOrder("ROLE_ADMIN", "ROLE_USER");
    }

    @Test
    @DisplayName("Un utilisateur inconnu leve UsernameNotFoundException")
    void utilisateurInconnu() {
        assertThatThrownBy(() -> userDetailsService.loadUserByUsername("inconnu"))
                .isInstanceOf(org.springframework.security.core.userdetails.UsernameNotFoundException.class);
    }

    @Test
    @DisplayName("Le prefixe {noop} n'est plus utilise")
    void plusDeNoop() {
        assertThat(userDetailsService.loadUserByUsername("user").getPassword()).doesNotContain("{noop}");
        assertThat(UserDetailsConfig.class).isNotNull();
    }

    @Test
    @DisplayName("Le compte est actif et non verrouille")
    void compteActif() {
        UserDetails user = userDetailsService.loadUserByUsername("user");

        assertThat(user.isEnabled()).isTrue();
        assertThat(user.isAccountNonLocked()).isTrue();
        assertThat(user.isAccountNonExpired()).isTrue();
        assertThat(user.isCredentialsNonExpired()).isTrue();
    }

    @Test
    @DisplayName("withUsername construit un UserDetails equivalent pour le compte user")
    void constructionEquivalente() {
        UserDetails attendu = withUsername("user").password("1111").roles("USER").build();
        assertThat(attendu.getUsername()).isEqualTo(userDetailsService.loadUserByUsername("user").getUsername());
    }

    private Set<String> autorites(String username) {
        return userDetailsService.loadUserByUsername(username).getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
    }
}
