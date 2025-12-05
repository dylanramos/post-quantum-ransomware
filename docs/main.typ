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
+ `Unlock one file` : pour déchiffrer un fichier spécifique et payer une plus petite rançon.

Le serveur propose l'option suivante :
+ `Change password` : pour changer le mot de passe utilisé pour dériver la clé principale.

== Option `Encrypt`

Une clé principale est dérivée d'un mot choisi aléatoirement dans un dictionnaire et une clé racine ainsi qu'une clé par fichier du dossier sont générées aléatoirement. Chaque fichier est ensuite chiffré avec sa clé dédiée et chacune de ces clés est chiffrée avec la clé racine. Enfin, la clé racine est chiffrée avec la clé principale.

#figure(
  image("img/01-tree.png", width: 70%),
  caption: [
    Arborescence des clés.
  ],
)

À noter que tous les chiffrements sont effectués avec *AES256-GCM*. Ainsi, pour chaque fichier, le nonce, le texte chiffré (clé du fichier chiffrée avec la clé racine) et le tag sont stockés dans les méta-données du fichier. Lorsque tous les fichiers sont chiffrés, la clé racine est chiffrée avec la clé principale.

Enfin, les deux paquets

== Niveau de sécurité choisi

Le ransomware utilise le niveau de sécurité *V*, qui offre une sécurité au moins aussi forte que AES-256.
