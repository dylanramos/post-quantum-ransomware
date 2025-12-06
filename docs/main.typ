#let title = "CAA - Mini-projet"
#let subtitle = "Ransomware post-quantique"
#let author = "Dylan Oliveira Ramos"
#let date = datetime.today().display("[day]-[month]-[year]")
#let logo = "./img/00-logo.png"

#set text(font: "New Computer Modern", lang: "fr")
#set heading(numbering: "1.")

#place(
  top + right,
  image(logo, width: 25%),
)

#place(
  horizon + center,
  align(center)[
    #line(length: 80%, stroke: 0.1pt)
    #v(0.4em)
    #text(2em, weight: 700, title)
    #v(0.4em)
    #line(length: 80%, stroke: 0.1pt)
    #v(1em)
    #text(1.2em, subtitle)
  ],
)

#place(
  bottom + left,
  align(left)[
    #text(1.2em, strong(author))
    #v(0.2em)
    #text(1.2em, date)
  ],
)

#pagebreak()

#set page(
  numbering: "1 / 1",
  number-align: center,
  header: [
    #author
    #h(1fr)
    #subtitle
    #line(length: 100%, stroke: 0.1pt)
  ],
)

= Description du ransomware

Nous avons un client (ordinateur de la victime) et un serveur (contrôlé par l'attaquant). Pour des raisons de simplicité, les deux entités sont exécutées dans le même programme.

Le client propose les options suivantes :
+ `Encrypt` : pour chiffrer tous les fichiers du dossier où se trouve le ransomware.
+ `Pay` : pour payer la rançon et obtenir la clé de déchiffrement.
+ `Decrypt one file` : pour déchiffrer un fichier spécifique et payer une plus petite rançon.

Le serveur propose l'option suivante :
+ `Change password` : pour changer le mot de passe utilisé pour dériver la clé principale.

== Niveau de sécurité choisi

Le ransomware utilise le niveau de sécurité *V*, qui offre une sécurité au moins aussi forte que AES-256.

== Algorithmes utilisés

=== Chiffrement symétrique

Pour le chiffrement symétrique, nous utilisons l'algorithme *AES256-GCM* avec les paramètres suivants :
- Taille de la clé : 256 bits.
- Taille du nonce : 96 bits.
- Taille du tag : 128 bits.

Ces paramètres nous permettent de chiffrer des fichiers d'une taille maximale d'environ 68 GB.

=== Chiffrement asymétrique

Pour le chiffrement asymétrique, nous utilisons l'algorithme post-quantique *Kyber1024* avec les paramètres suivants :
- Taille de la clé publique : 1568 bytes.
- Taille de la clé privée : 3168 bytes.

Cet algorithme nous permet de garantir une sécurité au moins aussi forte que AES-256.

=== Dérivation de clé

Pour dériver la clé principale à partir du mot de passe, nous utilisons l'algorithme *Argon2id* avec les paramètres suivants :
- Taille du sel : 16 bytes.
- Taille de la clé dérivée : 32 bytes.
- Nombre d'itérations : 1.
- Degré de parallélisme : 4.
- Coût en mémoire : 65536 KB.

Une taille de clé dérivée de 32 bytes nous permet d'obtenir une clé principale compatible avec AES-256.

== Chiffrement des fichiers

Le client et le serveur possèdent chacun une paire de clés publique/privée générée au démarrage du programme.

Lors du choix de l'option `Encrypt`, le ransomware effectue les étapes suivantes :
+ Le client obtient un d'un mot de passe aléatoire dans un dictionnaire, le chiffre avec la clé publique du serveur et lui envoie.
+ Le serveur dérive une clé avec Argon2id à partir du mot de passe reçu, chiffre sa clé privée avec AES en utilisant cette clé dérivée et l'envoie au client en la chiffrant avec la clé publique du client.
+ Le client déchiffre le message reçu avec sa clé privée et stocke la clé privée chiffrée du serveur dans un fichier à la racine du dossier.
+ Pour chaque fichier du dossier, le client génère une clé aléatoire et chiffre le fichier avec AES.
+ Chaque clé de fichier est chiffrée avec la clé publique du serveur et la suite clé chiffrée, nonce, tag, données chiffrées est stockée dans le fichier.

#figure(
  image("img/01-encryption.png", width: 70%),
  caption: "Étapes de chiffrement des fichiers.",
)

#figure(
  image("img/02-tree.png", width: 50%),
  caption: "Structure du dossier après chiffrement.",
)

Le fichier de la clé privée est structuré de la manière suivante :

`clé privée chiffrée || nonce || tag`

Les fichiers chiffrés de l'utilisateur sont structurés de la manière suivante :

`clé de fichier chiffrée || nonce || tag || données chiffrées`

== Paiement de la rançon

Lors du choix de l'option `Pay`, le ransomware effectue les étapes suivantes :
+ Le serveur envoie le mot de passe au client en le chiffrant avec la clé publique du client.
+ Le client déchiffre le message reçu avec sa clé privée, dérive une clé avec Argon2id à partir du mot de passe et déchiffre la clé privée du serveur avec AES.
+ Chaque clé de fichier est déchiffrée avec la clé privée du serveur.
+ Chaque fichier est déchiffré avec AES en utilisant la clé de fichier.

#figure(
  image("img/03-decryption.png", width: 70%),
  caption: "Étapes de déchiffrement des fichiers.",
)

== Déchiffrement d'un fichier spécifique

Lors du choix de l'option `Unlock one file`, le ransomware effectue les étapes suivantes :
+ Le client envoie la clé de fichier chiffrée au serveur.
+ Le serveur déchiffre la clé de fichier avec sa clé privée et l'envoie au client en la chiffrant avec la clé publique du client.
+ Le client déchiffre le message reçu avec sa clé privée et déchiffre le fichier avec AES en utilisant la clé de fichier.

#figure(
  image("img/04-decrypt-one-file.png", width: 70%),
  caption: "Étapes de déchiffrement d'un fichier spécifique.",
)