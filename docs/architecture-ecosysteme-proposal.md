# Proposition d'architecture : poste de travail Sécurix et son écosystème

Ce document est une proposition, ouverte à discussion, sur l'architecture
cible d'un poste de travail Sécurix et de l'écosystème NixOS qui
l'entoure, dans un contexte de déploiement multi-administrations gérées
de manière uniforme.

Il ne prétend pas prescrire : chaque proposition est défendable
isolément et peut être adoptée, adaptée ou rejetée. Le contexte
sous-jacent est le durcissement d'un poste admin au sens des guides
ANSSI PA-022 (administration sécurisée des SI) et NT-28 (durcissement
GNU/Linux), avec l'ambition de rester cohérent entre plusieurs
administrations tout en préservant la souveraineté de chacune sur ses
données et ses clés.

## 1. Principes directeurs

- **Souveraineté par administration** : chaque administration héberge
  et contrôle ses clés, secrets et journaux d'attestation. Aucun
  opérateur central n'est obligatoire.
- **Uniformité de gestion** : mêmes outils, mêmes procédures, mêmes
  baselines entre administrations. La divergence se fait par overlay
  déclaratif, pas par fork du noyau.
- **Composer plutôt que réinventer** : l'écosystème s'appuie sur des
  briques existantes auditables (lanzaboote, OpenBao, age, Kanidm…),
  pas sur un monolithe propriétaire.
- **Activation explicite (opt-in)** pour tout changement disruptif.
- **Assertions avec message clair** plutôt que `mkForce` silencieux,
  en pointant vers `security.anssi.excludes` ou équivalent.
- **Registre de flakes indépendants** : chaque satellite est un flake
  distinct, versionné et signé. Pas de mono-dépôt.

## 2. Modèle de menace retenu

### Scénarios couverts

- Accès physique bref (jusqu'à ~30 minutes) : vol opportuniste,
  poste égaré, attaquant en salle de réunion.
- Disque prélevé et analysé hors site.
- Compromission réseau locale (réseau WiFi hostile, LAN ouvert).
- Compromission d'un compte utilisateur (reprise de session,
  élévation de privilèges).
- Compromission légère de la chaîne d'approvisionnement logicielle.

### Scénarios hors périmètre

- Attaque matérielle sophistiquée (implant TPM, sonde JTAG,
  décapsulation de composants) : hors du budget défensif
  raisonnable d'un poste de travail.
- Cold boot attack sur la mémoire vive sans protections BIOS
  spécifiques : à traiter par module dédié si la flotte matérielle
  le permet.
- Attaquant disposant d'une présence hardware persistante.

### Justification du cadrage

L'attaque décrite par oddlama (contournement LUKS/TPM2 par confusion
de système de fichiers, 2025) est un scénario d'accès physique bref
aujourd'hui réaliste et documenté. Sans contre-mesure explicite, un
poste auto-déverrouillé par TPM est exposé. Le cadrage ci-dessus
impose une défense qui rend cet accès infructueux, tout en
reconnaissant les limites intrinsèques face à un attaquant étatique
persistant disposant d'accès matériel long.

## 3. Architecture en quatre couches

```
┌─────────────────────────────────────────────────────────┐
│ L3  Gestion de la flotte                                 │
│  Cache binaire admin, PKI, secrets dynamiques,           │
│  attestation continue, télémétrie d'intégrité            │
├─────────────────────────────────────────────────────────┤
│ L2  Satellites (flakes indépendants)                     │
│  securix-sat-bootchain, securix-sat-microseg,            │
│  securix-sat-logshipper, securix-sat-openbao-bridge,     │
│  securix-sat-fido2-fleet, etc.                           │
├─────────────────────────────────────────────────────────┤
│ L1  Profil d'administration (overlays sur L0)            │
│  securix-admin-MinistereX, politiques spécifiques,       │
│  niveau de sensibilité, matrice matériel supporté        │
├─────────────────────────────────────────────────────────┤
│ L0  Noyau Sécurix (cloud-gouv/securix)                   │
│  Baseline ANSSI commune, modules de durcissement, tests  │
└─────────────────────────────────────────────────────────┘
```

Chaque couche est une contribution distincte, versionnable et
substituable. Un satellite L2 peut être adopté par une administration
et refusé par une autre. Le noyau L0 reste le socle partagé.

## 4. Déploiement et sécurisation au démarrage

### 4.1 Chaîne de confiance cible

```
UEFI (Secure Boot, clés admin enrôlées)
 → lanzaboote stub (UKI signée par clé admin)
   → kernel (mesuré dans PCR 4)
     → initrd (hash intégré à l'UKI signée, non modifiable)
       → déchiffrement LUKS
          (policy TPM : PCR 0+2+4+7+15 + PIN utilisateur)
         → vérification applicative PCR 15 (ensure-pcr)
           → système cible monté
```

Deux barrières cryptographiques indépendantes protègent contre
l'attaque oddlama : la policy TPM refuse le déscellement si PCR 15
diverge, et le module `ensure-pcr` arrête le démarrage avec un
message explicite avant même la tentative de déscellement.

### 4.2 Infrastructure centralisée par administration

```
┌──────────────────────────────────────────────────────────────┐
│ Infrastructure admin (isolée, contrôle physique strict)       │
├──────────────────────────────────────────────────────────────┤
│ Artefacts statiques (git, versionnés) :                        │
│  • Flake admin (profil Sécurix + overlays + secrets chiffrés  │
│    age pour les destinataires autorisés)                      │
│  • Cache binaire Nix signé par clé admin                      │
│  • Image installeur NixOS signée                              │
│                                                                │
│ Serveurs actifs :                                              │
│  • Serveur PXE/iPXE (diffuse l'image installeur)              │
│  • OpenBao (PKI admin, secrets dynamiques, audit)             │
│  • Serveur de signature UKI (HSM, sollicité via OpenBao)      │
│                                                                │
│ Clés hors ligne (coffre physique, double contrôle) :           │
│  • Clé privée Secure Boot PK (racine)                         │
│  • Clé privée age "admin-bootstrap"                           │
│  • Sauvegardes Secure Boot KEK/db                             │
└──────────────────────────┬───────────────────────────────────┘
                           │ VLAN de provisionnement isolé
                           ▼
                ┌──────────────────────────┐
                │ Poste vierge              │
                │ TPM2 activé, SB en setup │
                └──────────────────────────┘
```

### 4.3 Déroulé de déploiement en 14 étapes

| # | Phase | Action | Outils |
|---|---|---|---|
| 1 | Amorçage réseau | Le poste démarre en PXE UEFI et récupère l'image installeur NixOS signée depuis le serveur de déploiement. | `pixiecore`, iPXE signée |
| 2 | Authentification | Le serveur PXE vérifie l'éligibilité (liste d'accès par adresse MAC + quote TPM initiale PCR 0/2/4/7). | ACL PXE + OpenBao |
| 3 | Identité locale | L'installeur génère une paire `age` unique pour ce poste. La clé privée est scellée localement dans un keystore protégé TPM. | `age-keygen` wrappé |
| 4 | Enregistrement | La clé publique `age` du poste est envoyée à OpenBao, signée par le certificat de l'installeur. | Client OpenBao embarqué |
| 5 | Enrôlement Secure Boot | L'installeur déchiffre PK/KEK/db admin depuis le flake (chiffrés `age` pour la clé "admin-bootstrap") puis `sbctl enroll-keys`. Retrait des clés Microsoft si la politique l'exige. | `sbctl`, `agenix` |
| 6 | Partitionnement | Application du plan déclaratif : ESP FAT32 + conteneur LUKS2 + BTRFS/LVM. | `disko` |
| 7 | Chiffrement disque (scellement initial) | Création LUKS2 avec volume key aléatoire. Scellement TPM : `--tpm2-pcrs=0+2+4+7 --tpm2-with-pin=yes`. PCR 15 volontairement absent (pas encore prédictible). Option `tpm2-measure-pcr=yes` ajoutée dans `/etc/crypttab` pour mesurer la volume key au déchiffrement suivant. | `systemd-cryptenroll` |
| 8 | Installation système | Installation de NixOS depuis le flake admin et le cache signé. Les secrets `age` destinés au poste sont déchiffrés à l'activation avec la clé locale. | `nixos-install`, `agenix` |
| 9 | Génération UKI | Demande de signature au serveur de signature via OpenBao, qui vérifie l'identité du poste (certificat machine + quote TPM) avant de signer. | `lanzaboote`, client OpenBao |
| 10 | Configuration initiale | `ensure-pcr.nix` activé avec `pcr15 = null`. `agenix` configuré avec l'identité locale. Service `first-boot-pcr-capture` armé. | Modules Nix |
| 11 | Premier démarrage | Secure Boot vérifie l'UKI. TPM + PIN déchiffre LUKS. `tpm2-measure-pcr=yes` mesure la volume key dans PCR 15. `first-boot-pcr-capture` lit PCR 15, signe la valeur avec la clé `age` locale, envoie à OpenBao. | `systemd-analyze pcrs`, client OpenBao |
| 12 | Enregistrement PCR | OpenBao vérifie la signature, enregistre PCR 15 attendu pour ce poste (indexé par `machine-id`), renvoie une valeur signée. | OpenBao PKI |
| 13 | Activation finale et rescellement TPM | La valeur signée est écrite dans le flake local. `nixos-rebuild switch` applique `systemIdentity.pcr15`. Rescellement : `--tpm2-pcrs=0+2+4+7+15 --tpm2-with-pin=yes`. La policy TPM refuse désormais le déscellement si PCR 15 diverge. | `nixos-rebuild`, `systemd-cryptenroll` |
| 14 | Enrôlement utilisateur | Première session : enrôlement de deux Yubikey FIDO2 (principale + sauvegarde), clés publiques enregistrées dans OpenBao. Le PIN TPM est renouvelé vers la valeur définitive choisie par l'utilisateur. | `pamu2fcfg`, hook OpenBao |

### 4.4 État cible après déploiement

- Secure Boot activé avec clés admin ; clés Microsoft retirées selon
  la politique.
- Chaîne de démarrage entièrement signée : firmware → lanzaboote →
  UKI (kernel + initrd).
- LUKS déchiffré uniquement si le TPM valide PCR 0/2/4/7/15 **et**
  si le PIN utilisateur est correct.
- Vérification `ensure-pcr` active en défense en profondeur.
- Identité `age` locale scellée dans le poste, identité publique
  enregistrée dans OpenBao.
- Deux Yubikey FIDO2 enrôlées.
- Attestation continue disponible via OpenBao.

### 4.5 Défenses croisées contre l'attaque oddlama

1. **Faux LUKS aux mêmes UUIDs** : volume key différente → PCR 15
   différent → policy TPM refuse le déscellement.
2. **Neutralisation de `ensure-pcr` dans l'initrd** : impossible,
   l'initrd est intégré à l'UKI signée (lanzaboote).
3. **Modification du kernel ou de l'initrd** : signature UKI invalide,
   Secure Boot refuse.
4. **Absence de PIN** : `--tpm2-with-pin=yes` impose la saisie
   manuelle à chaque démarrage.
5. **Boot hors machine avec matériel copié** : le TPM est lié au
   poste, la volume key ne sort jamais du TPM.

## 5. Industrialisation et maintien en condition opérationnelle

### 5.1 Gestion hybride des secrets : age et OpenBao

Les deux outils sont complémentaires, pas exclusifs.

| Secret / donnée | age (statique, dans le flake) | OpenBao (dynamique, runtime) |
|---|---|---|
| Clés publiques Secure Boot | ✅ | — |
| Clé privée Secure Boot PK (racine) | ❌ (hors ligne, coffre) | ❌ |
| Clé privée signature UKI | — | ✅ |
| Identité bootstrap (installeur) | ✅ | — |
| Policies signées distribuées | ✅ | — |
| Identité `age` locale du poste | Générée au provisionnement | — |
| Certificat machine renouvelable | — | ✅ |
| Jetons d'attestation | — | ✅ |
| PCR 15 attendu (signé) | Distribué dans le flake | ✅ (signature côté serveur) |
| Secrets applicatifs | — | ✅ |
| Credentials éphémères | — | ✅ |
| Sauvegardes de clés | ✅ (hors ligne) | — |

**Chaîne d'amorçage** :

1. L'image installeur contient la clé publique `age` "admin-bootstrap".
2. Au provisionnement, le poste génère sa propre paire `age` locale.
3. La clé publique locale est enregistrée dans OpenBao (authentifiée
   par le certificat de l'installeur).
4. Le poste obtient un premier certificat machine d'OpenBao en
   prouvant son quote TPM et sa signature `age` locale.
5. À partir de là, OpenBao gère le quotidien ; `age` couvre ce qui
   est versionné dans le flake.

**Modules NixOS mobilisables** : `agenix` (simple), `sops-nix` (plus
riche), module `openbao` déjà intégré à Sécurix.

### 5.2 Rotation des clés et cycle de vie

| Type de clé/secret | Fréquence | Portée | Automatisable | Risque en cas d'échec |
|---|---|---|---|---|
| PIN TPM | 12 mois + obligatoire au premier accès | Poste | Minuteur + notification utilisateur | Immobilisation du poste |
| Clé de volume LUKS | Annuelle ou sur incident | Poste (impact PCR 15) | Partiellement | Indisponibilité ~30 min |
| Secure Boot (PK/KEK/db) | 5 à 10 ans ou sur incident | Flotte entière | Non (double contrôle obligatoire) | Immobilisation de la flotte |
| Clé de signature UKI | Annuelle | Flotte | Oui (via le flake) | UKI invalide, démarrage impossible |
| Certificat machine (PKI OpenBao) | Hebdomadaire à mensuelle | Poste | Oui (agent local) | Attestation expirée, mise en quarantaine |
| Clé FIDO2 utilisateur | Événementielle (perte, départ) | Utilisateur | Partiellement | Perte d'accès utilisateur |
| Jetons et secrets applicatifs | Horaire à hebdomadaire | Agent applicatif | Oui (courte durée + renouvellement auto) | Délai de tolérance dépassé, blocage |

**Trois principes transverses** :

- **Versionnement via le flake admin** : chaque rotation est un
  commit traçable et auditable. Retour arrière possible par
  `nixos-rebuild switch --rollback`.
- **Déploiement progressif par vagues** : 1 poste pilote → 10 % → 50 %
  → 100 %. Pause automatique si une anomalie d'attestation est
  détectée par OpenBao.
- **Période de coexistence** : toute rotation accepte l'ancienne et
  la nouvelle valeur pendant une fenêtre configurable. Jamais de
  bascule brutale.

### 5.3 Mises à jour de la flotte

Chaque mise à jour est un commit dans le flake admin. Le déploiement
suit le même modèle progressif : pilote, élargissement partiel,
généralisation. Toute régression détectée par l'attestation (PCR
quote inattendu, échec de démarrage) déclenche une pause automatique.

### 5.4 Attestation continue

Chaque poste publie périodiquement à OpenBao :

- Une quote TPM signée (PCR 0/2/4/7/15).
- Le hash de la closure système active.
- Le hash de l'UKI en cours.
- Un compteur anti-rejeu.

OpenBao compare aux valeurs attendues signées pour chaque poste.
Toute divergence déclenche une alerte opérateur et peut, selon la
politique de l'administration, révoquer l'accès du poste aux
secrets applicatifs.

## 6. Gestion des identités sans annuaire LDAP/AD

### 6.1 Choix architectural

L'absence d'annuaire LDAP ou Active Directory par défaut est un
choix structurant. Il évite :

- un point de défaillance unique (annuaire indisponible =
  flotte bloquée) ;
- une surface d'attaque classique (injections LDAP, relais Kerberos) ;
- une dépendance à une infrastructure Windows incompatible avec un
  environnement 100 % Linux souverain ;
- une complexité de maintien en condition opérationnelle
  disproportionnée au regard du besoin d'un poste admin.

Ce choix impose en contrepartie de fournir des alternatives
industrielles pour la gestion des utilisateurs à l'échelle.

### 6.2 Propositions

Trois approches, à discuter selon la taille et la maturité de
l'administration cible.

**Proposition 1 — Kanidm (recommandation par défaut).** Serveur
d'identité moderne, écrit en Rust, avec support WebAuthn/FIDO2
natif. Il offre authentification FIDO2 sans secret partagé,
groupes et RBAC, délégation, intégration PAM via `pam_kanidm`,
interface OIDC pour les services web, compatibilité LDAP en
lecture seule si nécessaire. Module NixOS officiel.

```
Poste admin ── FIDO2 + pam_kanidm ──▶ Serveur Kanidm (admin)
                                              │
                                              ▼
                                        OpenBao (secrets)
```

**Proposition 2 — Authentik ou Keycloak (flottes plus grandes).**
Pour les administrations qui ont déjà investi dans ces outils,
l'intégration via OIDC reste possible. Plus lourd que Kanidm, mais
plus riche fonctionnellement (workflows multi-niveaux, délégation
avancée).

**Proposition 3 — OpenBao et FIDO2 direct (petites flottes).** Pour
une flotte inférieure à ~50 postes, OpenBao peut servir directement
de référentiel d'identité : chaque utilisateur est une entrée
OpenBao avec une clé publique FIDO2. Pas d'annuaire dédié, mais
mobilisation d'un outil déjà présent.

### 6.3 Cycle de vie utilisateur

- **Arrivée** : création dans Kanidm (ou équivalent), enrôlement
  de deux Yubikey FIDO2 (principale + sauvegarde), émission d'un
  certificat utilisateur par OpenBao PKI pour l'accès aux services.
- **Changement de rôle** : modification des groupes dans Kanidm,
  propagation automatique via `pam_kanidm`.
- **Perte d'une Yubikey** : révocation de la clé publique dans
  Kanidm, utilisation de la Yubikey de secours, émission d'une
  Yubikey de remplacement après vérification d'identité.
- **Départ** : désactivation du compte (conservation des journaux
  d'audit pour la durée réglementaire), révocation de tous les
  certificats OpenBao, retrait des Yubikey, effacement sécurisé du
  poste si restitution.

### 6.4 Intégration NixOS

Modules existants mobilisables :

- `services.kanidm` (module NixOS officiel).
- `security.pam.services.<name>.kanidm` pour l'authentification PAM.
- `services.kanidm-ssh-authorizer` pour les clés SSH.

Une option Sécurix pourrait synthétiser ces choix :

```nix
services.securix.identity = {
  backend = "kanidm";
  server = "kanidm.admin.gouv.fr";
  enrollment.requireTwoFidoKeys = true;
  # ...
};
```

## 7. Questions ouvertes

- **Matrice matériel supporté** : la rotation de PK Secure Boot
  nécessite un firmware UEFI compatible (variable `SetupMode`
  accessible, ou `db-update.auth` runtime). Tous les constructeurs
  ne le permettent pas. Une matrice maintenue collectivement
  serait précieuse.
- **Promotion de modules entre administrations** : comment promouvoir
  un module L2 développé par une administration vers le noyau L0 s'il
  est utile à d'autres ? Processus de revue, critères d'acceptation,
  gouvernance à définir.
- **Rotation coordonnée Secure Boot** : si deux administrations
  partagent du matériel (postes recyclés, prêts), la rotation doit
  être coordonnée. Modalités à discuter.
- **Attestation et conformité RGPD** : l'attestation continue produit
  des journaux côté OpenBao. Conformité à examiner (nature des
  données, durée de conservation, finalité).

## 8. Références

- ANSSI PA-022 v3.0, *Recommandations pour la sécurisation d'un
  système d'administration*.
- ANSSI NT-28 v2.0, *Recommandations pour la mise en œuvre de
  GNU/Linux dans un environnement de confiance*.
- oddlama, « Bypassing Disk Encryption with TPM2 Unlock » (janvier
  2025), <https://oddlama.org/blog/bypassing-disk-encryption-with-tpm2-unlock/>.
- patrick (lel.lol), module `ensure-pcr.nix`,
  <https://forge.lel.lol/patrick/nix-config/src/branch/master/modules/ensure-pcr.nix>.
- nix-community/lanzaboote, <https://github.com/nix-community/lanzaboote>.
- openbao/openbao, <https://github.com/openbao/openbao>.
- ryantm/agenix, <https://github.com/ryantm/agenix>.
- Mic92/sops-nix, <https://github.com/Mic92/sops-nix>.
- kanidm/kanidm, <https://github.com/kanidm/kanidm>.
- Lennart Poettering, « Brave New Trusted Boot World » (octobre 2022).
