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

Nous avons un client (ordinateur de la victime) et un serveur (contrôlé par l'attaquant), le serveur possède une paire de clés publique/privée pour l'établissement d'un secret partagé et une pour signer les messages. Les deux clés publiques sont intégrées au ransomware (client). Pour des raisons de simplicité, les deux entités sont exécutées dans le même programme.

Le programme propose les options suivantes :
+ `Encrypt` : pour chiffrer tous les fichiers d'un dossier choisi.
+ `Pay` : pour payer la rançon et pouvoir déchiffrer tous les fichiers.
+ `Decrypt one file` : pour déchiffrer un fichier spécifique et payer une plus petite rançon.
+ `Change password` : pour changer le mot de passe utilisé pour tout déchiffrer.

== Niveau de sécurité choisi

Le ransomware utilise le niveau de sécurité *V*, qui offre une sécurité au moins aussi forte que AES-256.

== Communication entre le client et le serveur

=== Établissement de la communication sécurisée

Au lancement du programme, le client et le serveur établissent un secret partagé en utilisant l'algorithme *Kyber-1024*. Ce secret partagé est ensuite dérivé avec *HKDF* pour obtenir une clé symétrique utilisée pour chiffrer les communications entre le client et le serveur avec *AES-256-GCM*.

#figure(
  image("img/01-communication.png", width: 80%),
  caption: [
    Établissement de la clé symétrique pour la communication sécurisée entre le client et le serveur.
  ],
)

=== Paramètres utilisés

*Kyber-1024* :
- Taille de la clé publique : 1568 bytes.
- Taille de la clé privée : 3168 bytes.

*HKDF* :
- Algorithme de hachage : SHA-256.
- Taille de la clé dérivée : 32 bytes (pour être compatible avec AES-256).
- Sel : aucun.

*AES-256-GCM* :
- Taille de la clé : 32 bytes.
- Taille du nonce : 12 bytes.
- Taille du tag : 16 bytes.

=== Résistance aux attaques post-quantiques

Cette architecture est résistante aux attaques post-quantiques car // TODO

== Chiffrement des fichiers

=== Types de clés

Trois types de clés utilisés lors du chiffrement des fichiers :
- `Master Key` : clé dérivée avec *Argon2id* à partir d'un mot de passe aléatoire d'un dictionnaire (`Master Password`).
- `Root Key` : clé générée de manière aléatoire, utilisée pour chiffrer les `File Key` avec *AES-GCM*.
- `File Key` : clé dérivée avec *Argon2id* à partir d'un mot de passe aléatoire du dictionnaire, unique pour chaque fichier, utilisée pour chiffrer le fichier avec *AES-GCM*.

=== Processus de chiffrement

Lors du choix de l'option `Encrypt`, le client :
+ Chiffre chaque fichier du dossier avec sa `File Key` respective.
+ Chiffre chaque `File Key` avec la `Root Key`.
+ Chiffre la `Root Key` avec la `Master Key`.
+ Stocke la `Root Key` chiffrée et les métadonnées dans un fichier à la racine du dossier.

#figure(
  image("img/02-file-encryption.png", width: 90%),
  caption: [
    Chiffrement des fichiers et des clés de fichier sur le client.
  ],
)

#figure(
  image("img/03-root-key-encryption.png", width: 30%),
  caption: [
    Chiffrement de la `Root Key` sur le client.
  ],
)

=== Paramètres utilisés

*Argon2id* :
- Taille du sel : 16 bytes.
- Taille de la clé dérivée : 32 bytes (pour être compatible avec AES-256).
- Nombre d'itérations : 1.
- Degré de parallélisme : 4.
- Coût en mémoire : 65536 KB.

*AES-256-GCM* :
- Taille de la clé : 32 bytes.
- Taille du nonce : 12 bytes.
- Taille du tag : 16 bytes.

Ces paramètres permettent de chiffrer des fichiers d'une taille maximale d'environ 68 GB.

=== Structure des fichiers chiffrés

Le tableau ci-dessous montre la structure d'un fichier chiffré, chaque donnée est concaténée dans l'ordre indiqué.

#table(
  columns: (auto, auto, auto, auto, auto, auto, auto, auto),
  align: horizon + center,
  [File ID],
  [Password Salt],
  [File Key IV],
  [File Key Tag],
  [File Key Ciphertext],
  [File IV],
  [File Tag],
  [File Ciphertext],
)

Le tableau ci-dessous montre la structure du fichier créé à la racine du dossier, chaque donnée est concaténée dans l'ordre indiqué.

#table(
  columns: (auto, auto, auto, auto, auto),
  align: horizon + center,
  [File ID], [Master Password Salt], [Root Key IV], [Root Key Tag], [Root Key Ciphertext],
)

_Note : Le `File ID` 0 est réservé pour le fichier de métadonnées à la racine._

=== Envoi des mots de passe au serveur

Une fois le chiffrement terminé, le client envoie tous les mots de passes utilisés pour dériver les clés (`Master Password` et `File Passwords`) au serveur en chiffrant le tout avec la `Communication Key`.

#figure(
  image("img/04-send-passwords-to-server.png", width: 80%),
  caption: [
    Envoi des mots de passe au serveur.
  ],
)

== Paiement de la rançon

== Déchiffrement d'un fichier spécifique

== Changement de mot de passe

== Spécificités

=== Pourquoi l'architecture est résistante aux attaques post-quantiques ?

=== Pourquoi le niveau de sécurité V est le même partout ?

=== Qu'est-ce qui permet au ransomware d'être sûr que le mot de passe est légitime ?

// TODO : signer le mot de passe avec la clé privée du serveur et inversement pour le client
