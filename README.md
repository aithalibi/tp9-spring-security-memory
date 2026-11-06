# TP 9 — Authentification en mémoire avec Spring Security

Application Spring Boot / Thymeleaf démontrant la mise en place d'une **authentification en mémoire** avec Spring Security : deux comptes statiques (`user`, `admin`), des mots de passe hachés en **BCrypt**, une page de connexion personnalisée et une autorisation par rôle (`ROLE_USER`, `ROLE_ADMIN`).

> Cours : *Développement JakartaEE : Spring* — TP 9 (lab 208)

---

## 1. Objectifs pédagogiques

- Comprendre le modèle d'authentification / autorisation de Spring Security.
- Créer et administrer des utilisateurs et des rôles **en mémoire**.
- Restreindre l'accès aux URLs selon le rôle attribué (`hasRole`, `anyRequest().authenticated()`).
- Personnaliser la page de connexion et la page d'accès refusé.
- Hacher les mots de passe avec `BCryptPasswordEncoder` (plus jamais de `{noop}`).

---

## 2. Architecture du projet

```
tp9-spring-security
├── pom.xml
├── README.md
├── docs
│   ├── build.log
│   ├── tests.log
│   └── images/            (captures des scénarios de validation)
└── src
    ├── main
    │   ├── java/ma/fstg/security
    │   │   ├── SpringSecurityDemoApplication.java
    │   │   ├── config
    │   │   │   ├── SecurityConfig.java        # SecurityFilterChain
    │   │   │   └── UserDetailsConfig.java     # encodeur + utilisateurs en mémoire
    │   │   └── web
    │   │       ├── HomeController.java        # /, /user/**, /admin/**, /acces-refuse
    │   │       └── ProfilController.java      # /profil (inspection de l'Authentication)
    │   └── resources
    │       ├── application.properties
    │       ├── static/css/style.css
    │       └── templates
    │           ├── fragments.html
    │           ├── index.html
    │           ├── login.html
    │           ├── user_dashboard.html
    │           ├── admin_dashboard.html
    │           ├── acces_refuse.html
    │           └── profil.html
    └── test/java/ma/fstg/security
        ├── SecurityConfigTest.java            # 12 tests MockMvc
        └── UserDetailsConfigTest.java        # 9 tests sur l'encodeur et les rôles
```

---

## 3. Dépendances (`pom.xml`)

| Dépendance | Rôle |
|---|---|
| `spring-boot-starter-web` | Contrôleurs MVC |
| `spring-boot-starter-thymeleaf` | Moteur de templates |
| `spring-boot-starter-security` | Filtres d'authentification / autorisation |
| `thymeleaf-extras-springsecurity6` | Attributs `sec:authorize`, `sec:authentication` |
| `spring-boot-starter-test` | JUnit 5, AssertJ, MockMvc |
| `spring-security-test` | `@WithMockUser`, `csrf()`, `formLogin()` |

Version du parent : **Spring Boot 3.3.5**, Java **17**.

---

## 4. Configuration de la sécurité

### 4.1 Chaîne de filtres — `SecurityConfig`

```java
http
    .authorizeHttpRequests(auth -> auth
        .requestMatchers("/", "/login", "/css/**", "/acces-refuse", "/error").permitAll()
        .requestMatchers("/user/**").hasRole("USER")
        .requestMatchers("/admin/**").hasRole("ADMIN")
        .anyRequest().authenticated()
    )
    .formLogin(form -> form
        .loginPage("/login")
        .defaultSuccessUrl("/", false)
        .failureUrl("/login?error")
        .permitAll()
    )
    .logout(logout -> logout
        .logoutUrl("/logout")
        .logoutSuccessUrl("/login?logout")
        .invalidateHttpSession(true)
        .deleteCookies("JSESSIONID")
        .permitAll()
    )
    .exceptionHandling(ex -> ex.accessDeniedPage("/acces-refuse"));
```

Points clés :

- `permitAll()` sur les ressources publiques puis **`anyRequest().authenticated()`** en dernière position : tout ce qui n'est pas explicitement ouvert est protégé (principe du moindre privilège).
- `hasRole("ADMIN")` attend une autorité nommée `ROLE_ADMIN` (Spring ajoute automatiquement le préfixe).
- `defaultSuccessUrl("/", false)` conserve la page demandée initialement lorsqu'elle existe.
- `accessDeniedPage("/acces-refuse")` remplace la page d'erreur blanche par une vue explicative.

### 4.2 Utilisateurs en mémoire — `UserDetailsConfig`

```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}

@Bean
public UserDetailsService userDetailsService(PasswordEncoder encoder) {
    UserDetails user = User.withUsername("user")
            .password(encoder.encode("1111"))
            .roles("USER")
            .build();
    UserDetails admin = User.withUsername("admin")
            .password(encoder.encode("1234"))
            .roles("ADMIN", "USER")
            .build();
    return new InMemoryUserDetailsManager(user, admin);
}
```

Les mots de passe sont **encodés au démarrage** : la base mémoire ne contient que des hachages `$2a$…`, jamais les valeurs en clair.

### 4.3 Comptes de démonstration

| Identifiant | Mot de passe | Rôles | Accès |
|---|---|---|---|
| `user` | `1111` | `ROLE_USER` | `/user/dashboard`, `/profil` |
| `admin` | `1234` | `ROLE_ADMIN`, `ROLE_USER` | tout, dont `/admin/dashboard` |

---

## 5. Routes exposées

| Méthode | URL | Accès | Vue |
|---|---|---|---|
| GET | `/` | public | `index.html` |
| GET | `/login` | public | `login.html` |
| POST | `/login` | public | traitement Spring Security |
| POST | `/logout` | authentifié + CSRF | redirection `/login?logout` |
| GET | `/user/dashboard` | `ROLE_USER` | `user_dashboard.html` |
| GET | `/admin/dashboard` | `ROLE_ADMIN` | `admin_dashboard.html` |
| GET | `/profil` | authentifié | `profil.html` |
| GET | `/acces-refuse` | public | `acces_refuse.html` |

---

## 6. Lancer l'application

```bash
# Compilation + tests + packaging
mvn clean package

# Exécution
java -jar target/spring-security-demo-1.0.0.jar
# ou
mvn spring-boot:run
```

L'application écoute sur **http://localhost:8080**.

---

## 7. Validation fonctionnelle (Étape 9 du TP)

Chaque scénario a été vérifié à la fois par un test MockMvc automatisé et manuellement dans un navigateur.

| # | Scénario | Résultat attendu | Constat |
|---|---|---|---|
| 1 | `GET /` sans session | 200, page publique | ✅ |
| 2 | `GET /user/dashboard` sans session | 302 → `/login` | ✅ |
| 3 | Connexion `user` / `1111` | 302 → `/`, session ouverte | ✅ |
| 4 | `GET /user/dashboard` avec `user` | 200 | ✅ |
| 5 | `GET /admin/dashboard` avec `user` | **403** + vue « Accès refusé » | ✅ |
| 6 | Connexion `user` / mauvais mot de passe | 302 → `/login?error` | ✅ |
| 7 | Connexion `admin` / `1234` | 302 → `/` | ✅ |
| 8 | `GET /user/dashboard` avec `admin` | 200 | ✅ |
| 9 | `GET /admin/dashboard` avec `admin` | 200 | ✅ |
| 10 | `POST /logout` | 302 → `/login?logout`, session invalidée | ✅ |
| 11 | `GET /profil` avec `user` | 200, principal = `user`, autorités `[ROLE_USER]` | ✅ |

### Captures d'écran

| Fichier | Contenu |
|---|---|
| `docs/images/01-accueil.png` | Page d'accueil publique |
| `docs/images/02-login.png` | Formulaire de connexion personnalisé |
| `docs/images/03-accueil-connecte.png` | Accueil après connexion (`user`) |
| `docs/images/04-espace-user.png` | Espace utilisateur |
| `docs/images/05-acces-refuse.png` | Refus 403 sur `/admin/dashboard` pour `user` |
| `docs/images/06-profil.png` | Page profil : lecture du `SecurityContext` |
| `docs/images/07-deconnexion.png` | Message de déconnexion |
| `docs/images/08-espace-admin.png` | Espace administrateur (`admin`) |

---

## 8. Tests automatisés

```bash
mvn test
```

Résultat obtenu (`docs/tests.log`) :

```
Tests run: 12, Failures: 0, Errors: 0, Skipped: 0 -- SecurityConfigTest
Tests run:  9, Failures: 0, Errors: 0, Skipped: 0 -- UserDetailsConfigTest
Tests run: 21, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

### `SecurityConfigTest` (MockMvc)

Vérifie la chaîne de filtres : accès public, redirection vers `/login`, connexion réussie/échouée des deux comptes, refus 403 avec redirection vers `/acces-refuse`, déconnexion, contenu des vues.

### `UserDetailsConfigTest`

Vérifie la couche « utilisateurs » indépendamment du web :

- l'encodeur produit bien du BCrypt (`$2a$`), jamais le mot de passe en clair ;
- deux encodages du même mot de passe donnent des hachages différents (sel aléatoire) ;
- `user` possède `ROLE_USER`, `admin` possède `ROLE_ADMIN` et `ROLE_USER` ;
- un identifiant inconnu lève `UsernameNotFoundException` ;
- aucun compte ne contient le préfixe `{noop}`.

> Astuce Spring Security 6 : `SecurityMockMvcRequestBuilders.logout()` ne propose pas `.with(...)`. Pour tester la déconnexion avec un utilisateur et un jeton CSRF, on écrit `post("/logout").with(user("user")).with(csrf())`.

---

## 9. Bonnes pratiques appliquées (Étape 10)

- **Encodage obligatoire** : `BCryptPasswordEncoder` (alternative : `Argon2PasswordEncoder`). Aucun mot de passe en clair.
- **Moindre privilège** : `anyRequest().authenticated()` en fin de chaîne ; seul le strict nécessaire est en `permitAll()`.
- **Centralisation** : toutes les règles sont dans `SecurityConfig` (`@Configuration` + `@EnableWebSecurity`).
- **Session** : `invalidateHttpSession(true)` et `deleteCookies("JSESSIONID")` à la déconnexion ; CSRF actif (le jeton est injecté par Thymeleaf dans chaque formulaire `th:action`).
- **Ne rien exposer d'inutile** : `eraseCredentialsAfterAuthentication` est actif par défaut, donc le mot de passe n'est plus lisible dans le `SecurityContext` après authentification (visible sur `/profil`).

---

## 10. Pistes d'amélioration

- Remplacer la mémoire par une base de données (TP 11 : `JpaUserDetailsService` + `DaoAuthenticationProvider`).
- Passer à une API REST sans état avec JWT (TP 12).
- Déléguer l'authentification à un fournisseur OAuth2/OIDC (TP 13).
- Ajouter `@PreAuthorize` pour des autorisations au niveau méthode.
