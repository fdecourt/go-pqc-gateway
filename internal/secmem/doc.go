// Package secmem regroupe la manipulation des octets secrets hors du cœur cryptographique :
// effacement explicite, tampons qui effacent leurs anciennes copies en grandissant, lecture
// bornée d'un flux dans un tampon possédé, et (dé)sérialisation JSON sans chaîne Go immuable
// pour les valeurs secrètes.
//
// Règle commune : un octet secret ne vit que dans un []byte dont l'appelant est propriétaire
// et qu'il efface (Wipe) dès qu'il n'en a plus besoin. Les copies faites par une bibliothèque
// (chaînes Go, tampons internes d'encoding/json ou d'io.ReadAll) sont évitées, car elles ne
// peuvent pas être effacées.
//
// Limites assumées : les tampons internes du runtime réseau (bufio du serveur HTTP, enregistrements
// TLS) et les registres ne sont pas couverts ici ; la compilation avec GOEXPERIMENT=runtimesecret
// (voir le paquet crypto) complète l'effacement côté calcul cryptographique.
package secmem
