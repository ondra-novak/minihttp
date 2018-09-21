# minihttp
minihttp server in C++17 (one file)

Jednoduchy http server, pro studijni ucely, napsan v C++17. Poskytuje pouze metodu GET a umoznuje servovat 
staticke HTML stranky, vcetne obrazku, CSS a javascriptu.

Nová verze zavádí možnost přidat dynamické stránky napsané libovolným jazykem komunikující protokolem VSCGI (viz dále)

Je napsan jako jeden C++ soubor a pouziva vyhradne STL a Linux POSIX funkce.

vzhledem k nekterym posixovym funkcim je portovatelny pouze na Unix/Linux platformu. Pouziva treba volani 
::open() a ::sendfile() pro rychle odeslani souboru socketem

Komentare jsou naspansane v cestine

Licence MIT

Napsal Ondrej Novak


# VSCGI

Zkratka VSCGI představuje **Very Stupid Common Gate Interface**. Myšlenka je podobná jako u CGI, pouze toto rozhraní je mnohem jednodušší a hloupější. Nicméně nabízí plnou kontrolu nad zpracováním jednotlivého requestu pomocí skriptu (bash scriptu) nebo externího programu. 

## Použití VSCGI

Skript nebo program podporující rozhraní VSCGI musí mít příponu **.vscgi** a být označen jako spustitelný. Může se nacházet kdekoliv v domovském adresáři. Pokud je vyvolán přes URL (a přitom se může nacházet v URI v cestě), tak místo jeho zobrazení je skript nebo externí program spuštěn.

## Protokol VSCGI

### Spuštění skriptu VSCGI

VSCGI program obdrží 3 parametry na příkazové řádce
 
  1. metodu (např POST)
  2. uri - pozor, posílá se relativní URI vůči poloze souboru. Tedy pokud je zavolán přímo VSCGI skript, je tento argument prázdný. Pokud se ale nachází v cestě,například `GET /path/myscript.vscgi/other/path`, pak druhý argument obsahuje `/other/path`
  3. protokol - identifikace protokolu, zde bude nejspíš HTTP/1.0 nebo HTTP/1.1
  
### Čtení hlaviček a těla requestu
  
Zbytek requestu, tedy hlavičky a tělo requestu (pokud jde o POST nebo PUT) obdrží skript přes `stdin`. Mezi hlavičkou a daty je prázdná řádka. Řádky jsou oddělené linuxovým stylem pouze LF navzdory tomu, že HTTP hlavičky používají CRLF. Proto je možné použít Bashovský příkaz `read X` pro čtení řádků hlaviček. 

Po prázdné řádce ukončené znakem LF začíná tělo požadavku. Pro jednoduchost není třeba zjišťovat Content-Length a počítat přečtené bajty. Tělo končí na EOF, tedy stačí číst standardní vstup, dokud není standardní vstup uzavřen.

### Odeslání odpovědi

**VSCGI script by měl vždy načíst celý request, než začne posílat odpověď**

Odpověď musí začínát status řádkou HTTP. Za ní by měla následovat hlavička Content-Type a pak další hlavičky. Za poslední hlavičkou je třeba udělat prázdnou řádku a to i v případě, že odpověď nenese žádné tělo (třeba při redirectu)

```
HTTP/1.1 200 OK
Content-Type: text/html

<html><head>....
```

## Limity protokolu VSCGI

 - požadavky POST a PUT musí mít Content-Length. Není podporován chunked encoding v requestu
 - request zpracovaný VSCGI nepodporuje keep-alive
 - websockety nefungují protože, že request je třeba celý načíst než lze odeslat odpověď. Tento způsob komunikace nevyhovuje 
 websocketům.
 
## Možnosti

Protokol je navržen tak, aby bylo možné ke statickým stránkám poskytovat nějaký základ pro vytváření makety API služeb. Typicky použití je v okamžiku, kdy skript ve stránce potřebuje odeslat nějaká data. VSCGI přitom nemusí data zpracovávat, pokud jde jen o maketu, pouze vygeneruje smysluplnou odpověď

Pomoci `curl` lze zařídit jednoduché tunelování, kdy lze tímto způsobem přeposílat requesty přímo na existující API, které by jinak nebylo možné kvůli nepovolenému CORS na cílovém API. 
