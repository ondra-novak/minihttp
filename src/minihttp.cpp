#include <iostream>
#include <string_view>
#include <thread>
#include <mutex>
#include <vector>
#include <sys/sendfile.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <iomanip>
#include <atomic>
#include <csignal>
#include <experimental/filesystem>

//Anonymni namespace protoze si v nekterych situacich prekladac stezuje (warning)
//vadi mu nejspis jeden velky soubor
namespace {

//deklarace nejakych opakujicih se konstant
static const char* APPLICATION_OCTET_STREAM = "application/octet-stream";
static const char* TEXT_HTML_CHARSET_UTF_8 = "text/html;charset=utf-8";

//Typ TextPair jednoduse obsahuje par dvou retezcu
//hodi se na key-hodnota zaznamy
using TextPair = std::pair<std::string_view, std::string_view>;

//tabulka prevud mezi priponou a mime typ
//tabulka je serazena podle klice, a pri pridavani novych typu je treba spravne zaradit
//jinak to prestane fungovat

static TextPair mime_types[] = {
		//ORDERED
		{"css","text/css;charset=utf-8"},
		{"gif","image/gif"},
		{"htm",TEXT_HTML_CHARSET_UTF_8},
		{"html",TEXT_HTML_CHARSET_UTF_8},
		{"jpg","image/jpeg"},
		{"js","text/javascript"},
		{"json","application/json"},
		{"png","image/png"},
		{"svg","image/svg"},
		{"xml","text/xml"}
};

///Deklarace vyjimky
/** na spouste mist se pracuje s posixovymi funkcemi, ktere generuji chybu v errno
 *  tato vyjimka nejen sejme errno, ale generuje i lidsky citelnou hlasku
 */
class ErrNoException: public std::runtime_error {
public:
	ErrNoException(const char *desc):std::runtime_error(buildMsg(errno,desc).c_str()) {}
protected:
	static std::string buildMsg(int err, const char *desc) {
		std::ostringstream bld;
		bld << desc << " - " << strerror(err) << "(" << err << ")";
		return bld.str();
	}

};

///Funkce slouzi k rychlemu zalogovani
/** vsechny parametry se zapisi do logu za sebou. Lze vlozit cokoliv co zvladne std::ostream */
template<typename ... Args> void log(Args && ... args );

///Sablona, ktera umoznuje snadno posixove objekty obalit do RAII
/**
 * @tparam T typ, ktery obaluju
 * @tparam CloseFn typ zaviraci funkce, mel by to byt pointer
 * @tparam pointer na zaviraci funkci. Tato funkce musi mit external linkage
 * @tparam invval pointer na promennou, ktera obsahuje neplatnou hodnotu, musi mit external linkage
 *
 * Objekt typu RAII predstavuje jednu instanci posixoveho objektu. Nelze jej kopirovat, pouze stehovat
 * pres pravou referenci &&, tim padem i vrace z funkce
 *
 */
template<typename T, typename CloseFn, CloseFn closeFn, const T *invval>
class RAII {
public:
	///Inicializuje na neplatnou hodnotu
	RAII():h(*invval) {}
	///inicializuje hodnotou
	RAII(T &&h):h(std::move(h)) {}
	///inicializuje hodnotou
	RAII(const T &h):h(h) {}
	///prenasi hodnotu z jednoho RAII objektu do jineho, puvodni objekt je invalidovan
	RAII(RAII &&other):h(other.h) {other.h = *invval;}
	///prenasi hodnotu z jednoho RAII objektu do jineho, puvodni objekt je invalidovan
	/** Pripadne uzavre aktualni objekt */
	RAII &operator=(RAII &&other) {
		if (this != &other) {
			close();
			h = other.h;
			other.h = *invval;
		}
		return *this;
	}
	///Konvertuje na puvodni hodnotu
	operator T() const {return h;}
	///Konvertuje na puvodni hodnotu
	T get() const {return h;}
	///umoznuje -> pristup, pokud jde o pointer
	T operator->() const {return h;}
	///zavre a znevalidni manualne
	void close() {
		if (!is_invalid())  closeFn(h);
		h = *invval;
	}
	///zavre a znevalidni implicitne pri destrukcc
	~RAII() {close();}
	///odebere objekt z RAII bez zniceni
	T detach() {T res = h; h = *invval; return res;}
	///vraci true, pokud obsahuje nevalidni objekt
	bool is_invalid() const {return h == *invval;}
	///vraci true, pokud obsahuje nevalidni objekt
	bool operator !() const {return is_invalid();}
	///vraci pointer na hodnotu
	///umoznuje pouzit RAII k inicializaci pres pointer
	T *ptr() {return &h;}
	///vraci pointer na hodnotu, tam kde je to nutne
	const T *ptr() const {return &h;}
protected:
	T h;

};

///Tato trida obsahuje pomocne definice RAII pro klasicky raw-pointer aby se nemusely deklarovat pro kazdy typ
/**
 * @tparam T typ
 */
template<typename T> class pointer_raii_traits_t {
public:
	///Obsahuje external linkage hodnotu nullptr
	static T *null;
	///funkce pro uvolneni pameti allokovane pres operator new(), external linkage
	static void free(T *x) {operator delete(static_cast<void *>(x));}
	///typ funkce free
	using FreeFn = decltype(&free);
	///kompletni deklarace RAII pro tento typ
	using RAII = ::RAII<T *, FreeFn, &pointer_raii_traits_t<T>::free, &null>;
};

template<typename T> T *pointer_raii_traits_t<T>::null = nullptr;

///hodnota pro invalid descriptor (external linkage)
static const int invalid_descriptor = -1;
///deklarace Socket, ktery je identifikova hodnotou typu int, zavira se funkci close a neplatna hodnota je -1
using Socket = RAII<int, decltype(&close), &close, &invalid_descriptor>;
///deklarace AddrInfo, jako RAII typu addrinfo *, zavira se funkci freeaddrinfo a neplatnou hodnotou je nullptr
using AddrInfo = RAII<addrinfo *, decltype(&freeaddrinfo), &freeaddrinfo, &pointer_raii_traits_t<addrinfo>::null>;

///Funkce se postara o otevreni portu
/**
 * @param portdef definice adresy a portu
 * @return otevreny socket
 */
static Socket open_port(const std::string_view &portdef) {
	//adresa a port jsou ve formatu <adresa>:<port>
	//platna je posledni dvojtecka (ktera je povinna), predchozi dvojtecky patri IPv6
	//napr ::1:<port>

	auto splt = portdef.rfind(':');
	//vysvedni addr do std::string - bohuzel, musi to koncit nulou
	std::string addr (portdef.substr(0,splt));
	//vysvedni addr do std::string - bohuzel, musi to koncit nulou
	std::string port (portdef.substr(splt+1));

	//deklaruj resolvovanou hodnotu
	AddrInfo resolved;
	//deklaruj hint
	struct addrinfo hint{};

	//chceme pasivni adresu (pro server)
	hint.ai_flags = AI_PASSIVE;
	//je nam jedno, jaky protokol
	hint.ai_family = AF_UNSPEC;
	//ale urcite stream (TCP)
	hint.ai_socktype = SOCK_STREAM;
	//najdi idealni definici
	if (getaddrinfo(addr.empty()?nullptr:addr.c_str(), port.c_str(),&hint, resolved.ptr())) {
		throw ErrNoException("getaddrinfo failed");
	}
	//otevri socket v potrebne AI_FAMILY
	Socket sock = socket(resolved->ai_family, SOCK_STREAM|SOCK_CLOEXEC, resolved->ai_protocol);
	if (!sock) throw ErrNoException("socket failed");

	//nastav tomu REUSEADDR
	//nekontroluj navratovou hodnotu. Nektere protokoly to neumi, takze kdyz to neprojde, tak se neda nic delat
	int flag = 1;
	(void)setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(int));

	//prirad adresu socketu
	if (bind(sock,resolved->ai_addr, resolved->ai_addrlen)) {
		throw ErrNoException("tcp bind failed");
	}
	//zacni naslouchat (otevri port)
	if (listen(sock,SOMAXCONN)) {
		throw ErrNoException("tcp listen failed");
	}

	//vypni NAGLE, opet se nekontroluje navratova hodnota, protoze to ma smysl jen pro TCP protokol
	(void)setsockopt(sock,IPPROTO_TCP,TCP_NODELAY,(char *) &flag,sizeof(int));
	return sock;
}

///Predstavuje otevrenou konekci
/** pro zkonstruovani potrebuje otevreny socket, zaroven ho prebira do vlastnictvi
 *  slouzi k snadnemu cteni a zapisu. Obsahuje cteci buffer
 *  */
class Conn {
public:
	///konstruktor
	explicit Conn(Socket &&sock);
	///cte ze socketu
	/** Provadi blokujici cteni. Funkce vraci vse co se dalo precist ze streamu a veslo se do bufferu. To
	 * co se neveslo je potreba nacist opakovanim volanim
	 *
	 * @return retezec nacteny ze socketu
	 */
	std::string_view read();
	/// vrati cast neprectenych dat zpet do streamu, takze pristi funkce read je opet vrati
	/**
	 * V pripade ze funkce zpracovavajici vstup nepotrebuje zbyvajici data, toutu funkci je vrati zpet
	 * do bufferu, takze dalsi read() je schopen data znova vratit a neztrati se. Ciste teoreticky jde
	 * vratit jiny buffer, ale je treba zajistit, aby buffer existoval dokud neni precten. Proto je dobre
	 * vracet vzdy cast bufferu ktery byl vytvoren funkci read()
	 *
	 * @param buff cast buffer, ktera se nevyuzila ke zpracovani, tato cast by mela pochazet z funkce read()
	 * n
	 */
	void put_back(const std::string_view &buff);
	///Precte radku
	/**
	 * @param ln retezec, ktery je naplnen radkou ze streamu. Predchozi obsah je vymazan. Pri cteni radek je
	 * dobre opakovane pouzivat jednu promennou bez jeji destrukce, protoze se tim redukuje pocet alokaci
	 * a dealokaci pri cteni
	 *
	 * @retval true nactena radka
	 * @retval false konec streamu, vic uz toho neni (druha strana zavrela spojeni)
	 */
	bool read_line(std::string &ln);

	///vraci referenci na aktivni socket
	const Socket &get_socket() const {return sock;}
	///zapise data
	/**
	 * @param data zapise data do streamu, blokujici volani, zapise se vzdy cely blok. Je dobre zapsat co
	 * nejvic na jeden zatah (je vypnuty NAGLE)
	 */
	void write(const std::string_view &data);

protected:
	Socket sock;
	char buffer[4096];
	std::string_view put_back_buff;
};

//socket je presunut do Conn
Conn::Conn(Socket &&sock):sock(std::move(sock)) {}

std::string_view Conn::read() {
	//pokud je vracen put_back buffer...
	if (!put_back_buff.empty()) {
		//tak se vyda jako vysledek
		auto tmp = put_back_buff;
		//zaroven se reference na buffer smaze (obsah bufferu ne)
		put_back_buff = std::string_view();
		return tmp;
	} else {
		//pokud neni put_back_buffer
		//pak nacti vse co jde do interniho bufferu
		int r = recv(sock,reinterpret_cast<unsigned char *>(buffer),sizeof(buffer),0);
		//pores jakekoliv chyby vyjimkou
		if (r < 0)
			throw ErrNoException("read failed");
		//vytvor pohled na buffer
		std::string_view out(buffer, r);
		//vrat ho jako vysledek
		//(pokud je buffer prazdny, je to konec)
		return out;
	}
}
void Conn::put_back(const std::string_view &buff) {
	//vraceni buffer je primitivni
	put_back_buff = buff;
}

bool Conn::read_line(std::string &ln) {
	//cteni cele radky
	//nejprve smaz radku
	ln.clear();
	//bude opsahovat pozici noveho radku
	std::size_t nwln;
	//obsahuje pohled na buffer nacteny ze streamu
	std::string_view data;
	do {
		//cti data
		data = read();
		//pokud se vratilo prazdno, pak oznam konec
		if (data.empty()) return false;
		//hledame dvojznak konce radky
		auto startpos = ln.length();
		//protoze je to dvojznak, je treba zacit o jeden znak drive, nez je konec predchozich dat
		if (startpos) startpos--;
		//pridej nactena data na konec radky (pripadne se nam spoji \r z predchoziho cteni a \n nasledujiciho cteni)
		ln.append(data);
		//najdi pozici \r\n od startpos
		nwln = ln.find("\r\n",startpos);
		//opakuj cteni, dokud neni nalezeno
	} while (nwln == ln.npos);
	//spocti jakou cast dat navic jsme precetli
	//tento remain buffer se ale bere jako substr z data,
	auto remain = data.substr(data.length()-(ln.length() - nwln - 2));
	//vrat ho do streamu
	put_back(remain);
	//orizni data radky tak, aby tam nebyl znak konce radky
	ln.resize(nwln);
	//uspech
	return true;
}

void Conn::write(const std::string_view &data) {
	//zapis co to da
	int r = send(sock, reinterpret_cast<const unsigned char *>(data.data()), data.length(), 0);
	//pokud se nezapsalo nic, tak to potichu ignoruj (co s tim?)
	if (r < 1) return;
	//pokud zbylo neco, co se nezapsalo
	auto more_data = data.substr(r);
	//opakuj zapis s tim zbytkem
	if (!more_data.empty()) write(more_data);
}

///Trida SplitString funguje jako statefull funkce, ktera rozreze string separatorem a postupne vraci jeho casti
class SplitString {
public:
	///Konstruuje funktor
	/**
	 * @param text text k rozrezani
	 * @param sep separator
	 * @param limit maximalni pocet casti (1-n)
	 */
	SplitString(const std::string_view &text, const std::string_view &sep, std::size_t limit):text(text),sep(sep),limit(limit) {}
	///Operator vraci true, pokud byl dosazen konec
	/**
	 * @retval true dosazen konec
	 * @retval false konec nedostazen
	 *
	 * @note Pokud chceme testovat, ze konec nebyl dosazen, pak pouzijeme dvojiteho vykricniku !!
	 */
	bool operator!() const {return reached_end;}
	///Funkce vraci dalsi cast v rozrezanem retezci.
	std::string_view operator()() {
		auto pos = limit < 2?text.npos:text.find(sep);
		if (pos == text.npos) {
			auto res = text;
			text = std::string_view();
			reached_end = true;
			return res;
		} else {
			--limit;
			auto res = text.substr(0,pos);
			text = text.substr(pos+sep.length());
			return res;
		}
	}
	///naplni promennou res hodnotou dalsi casti, a vraci referenci sama na sebe
	/**
	 * @param res referenci na pohled, ktery je inicializovan na dalsi cast
	 * @return referenci sama na sebe
	 *
	 * Priklad pouziti, hromadne rozrezani do nekalika promennych
	 * @code
	 * std::string_view a,b,c,d;
	 * SplitString(src,"/",4)(a)(b)(c)(d);
	 * @endcode
	 *
	 */
	SplitString &operator()(std::string_view &res) {res = operator()();return *this;}
protected:
	std::string_view text;
	std::string_view sep;
	std::size_t limit;
	bool reached_end = false;
};

///Predstavuje instanci serveru pro jedno spojeni
/** inicializuje se otevrenym socketem a cestou na docroot
 *
 */
class Server {
public:

	///Initializuje instanci serveru
	/**
	 * @param s otevreny socket
	 * @param docroot reference na retezec docroot
	 *
	 */
	Server(Socket &&s, const std::string &docroot, const std::string &index);
	///Spusti instanci serveru tim ze zacne vyrizovat pozadavky na zadanem spojeni
	void run() noexcept;


protected:
	Conn conn;			///< connection
	std::string docroot; ///< aktualni document root
	std::string hdrln; ///< radka obsahujici hlavick pozadavku (buffer)
	std::string ln;    ///< buffer pro radku zbyvajicich hlavicek
	std::string tmpln; ///< docasny buffer 1
	std::string tmpln2; ///< docasny buffer 2
	std::string outbuff; ///< vystupni buffer
	std::string index;  ///< index soubor

	///Bezi jeden cyklus
	/**
	 * @retval true zavolej znova pro dalsi cyklus
	 * @retval false ukonci cyklus
	 */
	bool run_1cycle();

	///odesle hlavicku odpovedi
	/**
	 * @param code status kod
	 * @param message status message
	 * @param httpver verze protokol (vetsinou se bere z requestu)
	 * @param beg iterator zacatku hlavicek
	 * @param end iterator konce hlavicek
	 * @param closeconn true, pokud se ma hlasit zavreni spojeni (prida Connection:close)
	 */
	template<typename Iterable>
	void send_response(int code, const std::string_view &message, std::string_view &httpver, Iterable &&beg, Iterable &&end, bool closeconn=false);

	///Deklarace typu, ktery predstavuje hlavicky zadane pomoci slozenych zavorek {}
	using InlineHeaders = std::initializer_list<TextPair>;
	///odesle hlavicku odpovedi pomoci InlineHeaders
	/**
	 *
	 * @param code status kod
	 * @param message status message
	 * @param httpver verze protokolu (vetsinou se bere z requestu)
	 * @param hdrs hlavicky jako initializer list
	 * @param closeconn true, pokud se ma hlasit zavreni spojeni (prida Connection:close)
	 */
	void send_response(int code, const std::string_view &message, std::string_view &httpver, InlineHeaders hdrs, bool closeconn=false) {
		send_response(code,message, httpver, hdrs.begin(), hdrs.end(), closeconn);
	}
	///Odesle error stranku
	/** Posle kompletni HTML stranku s chybovym kodem
	 *
	 * @param code status kod
	 * @param message status message
	 * @param httpver verze protokolu
	 */
	void send_error(int code, const std::string_view &message, std::string_view &httpver);

	///Funkce bezpecne mapuje uri na cestu do document root
	/**
	 * @param uri uri
	 * @return cesta vcetne document root
	 *
	 * @note uri muze obsahovat /../ ale ty se resi v ramci cesty, neprochazi se adresare a neni mozne opustit
	 * document root
	 */
	std::string map_uri_to_path(const std::string_view &uri);

	///Rychla funkce k prevodu celeho kladneho cisla na retezec
	/**
	 * @param number cislo k prevodu
	 * @param out vystupni retezec. Funkce nemaze obsah, cislo je pridano na konec
	 * @param level2 nechat false, funkce pouzive pri rekuzivnim volani sama sebe info o tom, ze je v rekurzi
	 */
	template<typename T> static void number_to_string(T number, std::string &out, bool level2 = false);

	///Vybere content-type souboru
	/**
	 * @param fpath cesta na soubor (cte se jen pripona)
	 * @return content-type
	 */
	static std::string_view determine_content_type(const std::string_view &fpath);

private:
};

Server::Server(Socket &&s, const std::string &docroot, const std::string &index)
	:conn(std::move(s))
	,docroot(docroot)
	,index(index) {}

void Server::run() noexcept {
	try {
		//cykluj dokud neni konec
		while (run_1cycle());

	} catch (std::exception &e) {
		//odchytni vyjimky a zaloguj
		log("Exception: ",e.what());
	}
}

bool Server::run_1cycle(){
	//precti prvni radku (request line), pokud selze, ukonci to

	if (!conn.read_line(hdrln)) return false;

	//request line musi byt zachovana po dobu requestu, protoze nasledujici
	//pohledy se odkazuji prave na request line.
	//kdyby se promenna hdrln zmenila, tyto promenne maji nedefinovany stav
	std::string_view cmd, uri, proto;

	//rozparsuj request line: command,mezera,uri,mezera,protocol
	SplitString(hdrln," ",3)(cmd)(uri)(proto);
	//tento server umi jen GET pozadavek, ostatni vyhod jako 405
	if (cmd != "GET") {
		send_error(405,"Method Not Allowed",proto);
		//ukonci spojeni pri chybe
		return false;
	}
	//ulozeni cesty
	std::string fpath;
	//info o tom, ze hlavicky jiz byly odeslany
	bool headers_sent = false;

	//vyjimky odchytni dale
	try {
		do {
			//cti zbyvajici radky hlavicky - pri konci streamu zahod request
			if (!conn.read_line(ln)) return false;
			//vsechny hlavicky zahod, tenhle server nic neumi
			//opakuj, dokud neni nalezena prazdna radka
		} while (!ln.empty());

		//mapuj uri na soubor
		fpath = map_uri_to_path(uri);

		//vyber content type
		std::string_view content_type = determine_content_type(fpath);

		//zjisti stav souboru
		auto fst = std::experimental::filesystem::status(fpath);

		//je to adresar?
		if (std::experimental::filesystem::is_directory(fst)) {
			//adresar nejde zobrazit
			//ale je treba udelat redirect pridanim lomitka /
			tmpln = uri;
			tmpln.append("/");
			//posli redirect
			send_response(301,"Permanent redirect", proto, {
					{"Location",tmpln},
					{"Content-Length","0"} //zadny obsah
					});
			//je to regulerni soubor
		} else if (std::experimental::filesystem::is_regular_file(fst)) {

			//zjisti velikost
			std::size_t size = std::experimental::filesystem::file_size(fpath);

			//preved velikost na retezec
			tmpln.clear();
			//je to rychlejsi nez pres std::ostringstream
			number_to_string(size,tmpln);

			//definuj typ PosixFile - zavira se pres close a neplatny descriptor ma -1
			using PosixFile = RAII<int, decltype(&close), &close, &invalid_descriptor>;
			//otevri soubor pro cteni
			PosixFile f = ::open(fpath.c_str(),O_RDONLY);
			//pokud se otevreni nepodarilo, tak oznam chybu
			if (!f) {
				throw ErrNoException("open failed");
			}

			//posli odpoved 200 OK s patricnym content-type a content-length (nepodporujeme chunked)
			send_response(200,"OK",proto,{
				{"Content-Type", content_type},
				{"Content-Length", tmpln}
			});

			headers_sent = true;

			//odesli soubor pomoci rychle funkce sendfile (pres kernel)
			//opakovane, dokud zbyva co odeslat
			while (size) {
				//odesli a zjisti kolik se odeslalo
				auto r = sendfile(conn.get_socket(), f, nullptr, size);
				//pokud to vrati -1, tak
				if (r < 1) {
					throw ErrNoException("sendfile failed");
				}
				//odecitej zbyvajici velikost
				size-=r;
			}
			//hotovo
		} else {
			//tohle vyhod jako vyjimku
			throw std::runtime_error("Unsupported file");
		}
		return true;

	} catch (std::exception &e) {
		//vsechny vyjimky zaloguj
		log("Exception: ", e.what(), "(path: '", fpath,"' )");
		//pokud nebyly odeslany hlavicky, vygeneruj error stranku 404 (maskujeme ze nic nevime)
		if (!headers_sent) send_error(404,"Not found",proto);
		//ukonci spojeni
		return false;
	}
}

template<typename Iterable>
inline void Server::send_response(int code, const std::string_view& message,
		std::string_view& httpver, Iterable&& beg, Iterable&& end,
		bool closeconn) {
	//v tehle funkci vytvorime hlavicky a odesleme je na klienta
	//pouziva se outbuff coz je std::string
	//to ma vyhodu, ze pri keep-alive se opakovane neprovadi alokace bufferu
	//vzdy se pouzije jiz alokovana pamet retezce

	//smaz retezec
	outbuff.clear();
	//vytvor prvni radku HTTP/1.0
	outbuff.append(httpver).append(" ");
	//status kod
	number_to_string(code, outbuff);
	//status message a enter
	outbuff.append(" ").append(message).append("\r\n");
	//projet vsechny hlavicky
	Iterable x = beg;
	while (x != end) {
		//pridej klic: hodnota enter
		outbuff.append(x->first).append(": ").append(x->second).append("\r\n");
		++x;
	}
	//pokud je closeconn true, pridej Connection: close a enter
	if (closeconn) {
		outbuff.append("Connection: close\r\n");
	}
	//pridej prazdnou radku
	outbuff.append("\r\n");
	//vse odesli naraz
	conn.write(outbuff);

	//zaloguj vyrizeny request
	log(hdrln, "(",code,")");
}

inline void Server::send_error(int code, const std::string_view& message, std::string_view& httpver) {
	//vygeneruje error stranku
	//odesli hlavicky
	send_response(code, message, httpver, {
			{ "Content-Type",TEXT_HTML_CHARSET_UTF_8 },
			{"Allow","GET"}},true);

	//tady uz pouzijeme stringstream, protoze jde o error stranku a nejaka rychlost nas netrapi

	std::ostringstream output;
	//vygeneruj html stranku
	output << "<html><body><h1>" << code << " " << message << "</h1>"
			<< "<hr><small><em>Powered by minihttp server written by <a href=\"https://github.com/ondra-novak/\">Ondrej Novak</a></em></small>"
			<< "</body></html>";
	//odesli vse
	conn.write(output.str());
}

std::string Server::map_uri_to_path(const std::string_view& uri) {
	//mapovani uri na cestu
	//pouzijeme jeden z docasnych bufferu - pravdepodobne uz ma neco predalokovano
	tmpln.clear();
	//rozdel cestu uri pres lomitka
	SplitString splt(uri,"/",(std::size_t)-1);
	//skip anything before /
	splt();
	//sem si poznacime, jestli posledni polozka byla odkazem na adresar (lomitko na konci)
	bool isdir = false;
	//dokud je odkud brat
	while (!!splt) {
		auto itm = splt();
		//vynuluj isdir (cokoliv co neni dir proste neni dir)
		isdir = false;
		//pokud je tam prazdno, tak to je dir
		if (itm.empty()) {
			//poznac
			//a vem dalsi
			isdir = true;
		} else if (itm == ".") {
			//tecka, jako by nebyla
			continue;
		} else if (itm == "..") {
			//dve tecky - jdi o level vyse
			//najdi posledni /
			auto pos = tmpln.rfind("/");
			//pokud neni, tak nastav pos na nulu
			if (pos == tmpln.npos) pos = 0;
			//smaz vsechno co je za pos
			tmpln.resize(pos);
		} else {
			//jinak appenduj vzdy lomitko
			tmpln.push_back('/');
			//a jmeno adresare
			tmpln.append(itm);
		}
	}
	//pokud nam zbyl odkaz na dir
	if (isdir) {
		//pridej / (protoze se nic nepridalo)
		tmpln.push_back('/');
		//pridej index
		tmpln.append(index);
	}

	//to sluc s docroot a cesta je na svete
	return docroot + tmpln;
}

template<typename T>
inline void Server::number_to_string(T number, std::string& out, bool level2) {
	//funkce prevadi cislo na retezec
	//dela to rekurzivne
	//tak ze cislo deli 10 az narazi na nulu
	//(obecne narazi na cislo mensi nez 1
	if (number < static_cast<T>(1)) {
		//na prvnim levelu napis 0, jinak nic (levostrane nuly nas netrapi)
		if (!level2) out.push_back('0');
	} else {
		//rekurzivne del cislo 10
		number_to_string(number/10, out, true);
		//pri navratu zpet zapis vzdy zbytek jako ascii cislo
		out.push_back('0' + static_cast<char>((number % 10)));
	}
}


inline std::string_view Server::determine_content_type(const std::string_view& fpath) {
	//funkce zjisti priponu a vybere content-type
	//pouzije k tomu tabulku mimes
	//nejprve najdeme tecku
	auto pos = fpath.rfind('.');
	//nenasli jsme tecku
	if (pos == fpath.npos)
		//posli binarni mime
		return APPLICATION_OCTET_STREAM;
	//nasli jsme tecku, zjisti priponu
	auto ext = fpath.substr(pos+1);
	//najdi v seznamu patricnou priponu
	auto iter = std::lower_bound(std::begin(mime_types), std::end(mime_types),TextPair(ext,""));
	//pokud je iterator na konci, nebo neco nasel a neni to ta pripona
	if (iter == std::end(mime_types) || iter->first != ext)
		//posli binarni mime
		return APPLICATION_OCTET_STREAM;
	//posli co jsi nasel
	return iter->second;
}

///SignalHandler zajistuje zpracovani signalu SIGTERM, SIGINT, SIGQUIT a SIGHUP
/** Protoze aplikace nema jiny zpusob, jak se ukoncit, pouzijeme signal aby se aplikace spravne ukoncila
 * Necheme to resit nasilne
 *
 * SignalHandler neni singleton, ale existuje neco jako cur_handler, ktery muze referovat jednu instanci
 * Pri vzniku signalu se zavola tato instance
 */
class SignalHandler {
public:
	///Vytvari objekt SignalHandler
	/**
	 * @param sock referenci na socket, ktery se pri ukonceni zavre
	 */
	SignalHandler(const Socket &sock):sock(sock) {}
	///Destruktor si zajisti, ze se signal handler odebere z aktualniho handleru
	~SignalHandler() {
		if (this == cur_handler) cur_handler = nullptr;
	}

	///Vraci true, pokud byl signal zachycen
	bool operator !() const {return !signaled;}
	///zachyti signal a zavre socket
	void signal() {
		signaled=true;
		//zavreni listen socketu se provede pres shutdown
		shutdown(sock, SHUT_RD);
	}

	///staticka funkce obsluhujici signal
	static void handler_proc(int) {
		///pokud je definovan handler, zavolej ho
		if (cur_handler) cur_handler->signal();
	}

	///nastav handler aktivni
	void make_active() {cur_handler = this;}

protected:
	static SignalHandler *cur_handler;
	const Socket &sock;
	bool signaled = false;
};

///aktivni handler
SignalHandler *SignalHandler::cur_handler = nullptr;


///Trida resi logovani z mnoha vlaken do jedno vystupniho streamu
/** Musi byt MT safe a protoze ma vnistrni stav, je to zalozeno jako objekt */
class LogObject {
public:
	///Vytvori instanci a spoji ji s nejakym streamem
	/**
	 * @param out refernce na vystupni stream
	 */
	LogObject(std::ostream &out):out(out) {}

	///Odesle log do stremau
	/**
	 * @param args libovolne mnozstvi argumentu
	 */
	template<typename ... Args>
	void send_log(Args && ... args) {
		//zamknu instanci, musime byt MT safe
		std::lock_guard<std::mutex> _(lk);
		//zjisti kolik je hodin
		time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
		//zapis cas
		out << std::put_time(std::localtime(&now), "%Y-%m-%d %X");
		//zapis index thread
		out << " [" << cur_thread_id << "] ";
		//zapis argumenty
		send_log_lk(std::forward<Args>(args)...);
		//udelej novou radku
		out << std::endl;
		//odemkni instanci
	}

	///Registruje novy thread
	/** To je tu hlavne proto, aby se v logu poznalo, co ktery thread udelal. Vzdy kdyz vznikne
	 * novy thread, je mu prideleno cislo pres citac, to cislo si pak te thread pamatuje a stim cislem
	 * se zapisuje do logu. Je to prehlednejsi nez pouzivat thread_id, ktery muze byt sileny hausnumero
	 * a velice neprehledny
	 */
	static void reg_thread() {
		cur_thread_id = ++thread_counter;
	}

protected:
	std::mutex lk;
	std::ostream &out;

	///zasilani argumentu - pro vice paramteru
	template<typename T, typename ... Args>
	void send_log_lk(T &&x, Args && ... args) {
		//zasli prvni parametr do streamu
		out << x;
		//rekurzivne volej po 2-n parametru
		send_log_lk(std::forward<Args>(args)...);
	}

	///kdyz uz zadny parametr nezbyl
	void send_log_lk() {}

	static std::atomic<unsigned int> thread_counter;
	static thread_local unsigned int cur_thread_id;

};

std::atomic<unsigned int> LogObject::thread_counter (0);
thread_local unsigned int LogObject::cur_thread_id = 0;

///tady mame globalni logovaci objekt
static  LogObject *globalLogObject;

///tato funkce loguje do globalniho logovaciho objektu
template<typename ... Args>
void log(Args && ... args) {
	globalLogObject->send_log(std::forward<Args>(args)...);
}

}

///hlavni funkce!
int main(int argc, char **argv) {

	//vytvor logovaci objekt, ktery loguje na stdout
	LogObject lg(std::cout);
	//ucin jej globalnim
	globalLogObject = &lg;

	//a ted uz odchytavej vyjimky
	try {
		//presne 3 argumenty musi byt
		if (argc != 3) {
			//jinak vypis help
			std::cerr << "Invalid arguments" << std::endl
					  << std::endl
					  << "Usage: " << argv[0] << " <addr:port> <path_to_document_root>" << std::endl;
			//a skonci
			return 1;
		}

		//deklaruj socket
		Socket sock;

		//nacti port
		std::string_view port(argv[1]);
		//pokud obsahuje dvojtecku
		if (port.find(':') != port.npos) {
			//otevri port a ziskej socket
			sock = open_port(port);
		} else  {
			//jinak oznam chybu
			std::cerr << "First argument must be <addr:port>"<<std::endl
					 <<std::endl
					 <<"127.0.0.1:12345   - open port 12345 on localhost"<<std::endl
					 <<"10.0.10.95:12345   - open port 12345 on specified interface"<<std::endl
					 <<":12345   - open port 12345 on all interfaces"<<std::endl;
			return 1;
		}

		//nacti document root
		std::string docroot(argv[2]);

		//inicializuj signal handler aby zaviral socket sock
		SignalHandler sig_hndl(sock);
		//ucin ho aktivnim
		sig_hndl.make_active();

		//ignoruj SIGPIPE
		std::signal(SIGPIPE,SIG_IGN);
		//ignoruj SIGCHLD
		std::signal(SIGCHLD,SIG_IGN);
		//registruj SIGQUIT
		std::signal(SIGQUIT,&SignalHandler::handler_proc);
		//registruj SIGTERM
		std::signal(SIGTERM,&SignalHandler::handler_proc);
		//registruj SIGINT
		std::signal(SIGINT,&SignalHandler::handler_proc);
		//registruj SIGHUP
		std::signal(SIGHUP,&SignalHandler::handler_proc);

		//zaloguj, ze jsme ready
		log("Server ready port: ", port);

		//nekonecna smycka
		for(;;) {
			//akceptuj spojeni
			Socket s (accept(sock, nullptr, 0));
			//pokud to selhalo?
			if (!s) {
				//tak pokud nebyl zachycen ukoncujici signal
				//znamena to, ze doslo k chybe
				if (!sig_hndl) {
					//vyhod vyjimku
					throw ErrNoException("accept failed");
				} else {
					//jinak je to chyba oznamujici shutdown
					//ukonci server
					break;
				}
			}

			//pro kazde spojeni spust vlakno, predej mu socket a document root
			std::thread thr([s = Socket(std::move(s)), &docroot] ()mutable {
				//zaregistruj nove vlakno
				LogObject::reg_thread();
				//vytvor instanci serveru
				Server srv(std::move(s), docroot,"index.html");
				//oznam nove spojeni do logu
				log("New connection");
				//spust server
				srv.run();
				//po skonceni serveru oznam uzavreni spojeni
				log("Connection closed");
			});
			//vlakno nehodlame joinovat, takze detach
			thr.detach();

		}

		//tady program konci
		log("Server exit");
		return 0;
	} catch (std::exception &e) {
		//oznam chybu, kdyz nastane vyjimka
		std::cerr << "ERROR:" << e.what() << std::endl;
		return 120;
	}
}

