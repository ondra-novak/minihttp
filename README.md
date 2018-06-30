# minihttp
minihttp server in C++17 (one file)

Jednoduchy http server, pro studijni ucely, napsan v C++17. Poskytuje pouze metodu GET a umoznuje servovat 
staticke HTML stranky, vcetne obrazku, CSS a javascriptu.

Je napsan jako jeden C++ soubor a pouziva vyhradne STL a Linux POSIX funkce.

vzhledem k nekterym posixovym funkcim je portovatelny pouze na Unix/Linux platformu. Pouziva treba volani 
::open() a ::sendfile() pro rychle odeslani souboru socketem

Komentare jsou naspansane v cestine

Licence MIT

Napsal Ondrej Novak
