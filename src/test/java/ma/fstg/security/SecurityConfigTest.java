package ma.fstg.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@SpringBootTest
@AutoConfigureMockMvc
class SecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("La page d'accueil est publique")
    void accueilAccessibleSansAuthentification() throws Exception {
        mockMvc.perform(get("/"))
                .andExpect(status().isOk())
                .andExpect(view().name("index"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("application publique")))
                .andExpect(unauthenticated());
    }

    @Test
    @DisplayName("Un anonyme est redirige vers la page de connexion")
    void espaceUtilisateurProtege() throws Exception {
        mockMvc.perform(get("/user/dashboard"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/login"));
    }

    @Test
    @DisplayName("Un anonyme ne peut pas atteindre la zone admin")
    void espaceAdminProtege() throws Exception {
        mockMvc.perform(get("/admin/dashboard"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/login"));
    }

    @Test
    @DisplayName("Le formulaire de connexion est accessible a tous")
    void pageLoginPublique() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"));
    }

    @Test
    @DisplayName("user / 1111 ouvre l'espace utilisateur")
    void connexionUtilisateurReussie() throws Exception {
        mockMvc.perform(formLogin("/login").user("user").password("1111"))
                .andExpect(status().is3xxRedirection())
                .andExpect(authenticated().withUsername("user"));

        mockMvc.perform(get("/user/dashboard").with(user("user").roles("USER")))
                .andExpect(status().isOk())
                .andExpect(view().name("user_dashboard"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Espace Utilisateur")));
    }

    @Test
    @DisplayName("admin / 1234 ouvre les deux espaces")
    void connexionAdminReussie() throws Exception {
        mockMvc.perform(formLogin("/login").user("admin").password("1234"))
                .andExpect(status().is3xxRedirection())
                .andExpect(authenticated().withUsername("admin").withRoles("ADMIN", "USER"));

        mockMvc.perform(get("/admin/dashboard").with(user("admin").roles("ADMIN", "USER")))
                .andExpect(status().isOk())
                .andExpect(view().name("admin_dashboard"));

        mockMvc.perform(get("/user/dashboard").with(user("admin").roles("ADMIN", "USER")))
                .andExpect(status().isOk())
                .andExpect(view().name("user_dashboard"));
    }

    @Test
    @DisplayName("Un mauvais mot de passe renvoie vers /login?error")
    void mauvaisMotDePasse() throws Exception {
        mockMvc.perform(formLogin("/login").user("user").password("mauvais"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?error"))
                .andExpect(unauthenticated());
    }

    @Test
    @DisplayName("Un compte USER est renvoye vers /acces-refuse sur la zone admin")
    void utilisateurRefuseSurZoneAdmin() throws Exception {
        MvcResult result = mockMvc.perform(get("/admin/dashboard").with(user("user").roles("USER")))
                .andExpect(forwardedUrl("/acces-refuse"))
                .andReturn();

        assertThat(result.getResponse().getStatus()).isIn(403, 200);
    }

    @Test
    @DisplayName("La page d'acces refuse est publique et affiche le role courant")
    void pageAccesRefuse() throws Exception {
        mockMvc.perform(get("/acces-refuse"))
                .andExpect(status().isOk())
                .andExpect(view().name("acces_refuse"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Acces refuse")));
    }

    @Test
    @DisplayName("La deconnexion redirige vers /login?logout")
    void deconnexion() throws Exception {
        mockMvc.perform(post("/logout").with(user("user").roles("USER")).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?logout"));
    }

    @Test
    @DisplayName("La page de profil expose le principal et ses autorites")
    void pageProfil() throws Exception {
        mockMvc.perform(get("/profil").with(user("admin").roles("ADMIN", "USER")))
                .andExpect(status().isOk())
                .andExpect(view().name("profil"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Mon profil")));
    }

    @Test
    @DisplayName("Une route inconnue sous /user exige tout de meme une authentification")
    void routeInconnueProtegee() throws Exception {
        mockMvc.perform(get("/user/inconnue"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/login"));
    }
}
