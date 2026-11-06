package ma.fstg.security.web;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ProfilController {

    @GetMapping("/profil")
    public String profil(Authentication authentication, Model model) {
        model.addAttribute("nom", authentication.getName());
        model.addAttribute("autorites", authentication.getAuthorities());
        return "profil";
    }
}
