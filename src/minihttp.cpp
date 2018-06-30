//============================================================================
// Name        : minihttp.cpp
// Author      : Ondrej Novak
// Version     :
// Copyright   : MIT Licence
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <cctype>
#include <iostream>
#include <string_view>
#include <thread>
#include <mutex>
#include <vector>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sstream>
#include <sys/un.h>
#include <fcntl.h>
#include <chrono>
#include <iomanip>
#include <atomic>
#include <csignal>

static const char* APPLICATION_OCTET_STREAM = "application/octet-stream";
static const char* TEXT_HTML_CHARSET_UTF_8 = "text/html;charset=utf-8";

using TextPair = std::pair<std::string_view, std::string_view>;
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

template<typename ... Args> void log(Args && ... args );

template<typename T, typename CloseFn, CloseFn closeFn, const T *invval>
class RAII {
public:
	RAII():h(*invval) {}
	RAII(T &&h):h(std::move(h)) {}
	RAII(const T &h):h(h) {}
	RAII(RAII &&other):h(other.h) {other.h = *invval;}
	RAII &operator=(RAII &&other) {
		if (this != &other) {
			close();
			h = other.h;
			other.h = *invval;
		}
		return *this;
	}
	operator T() const {return h;}
	T get() const {return h;}
	T operator->() const {return h;}
	void close() {
		if (!is_invalid())  closeFn(h);
		h = *invval;
	}
	~RAII() {close();}
	T detach() {T res = h; h = *invval; return res;}
	bool is_invalid() const {return h == *invval;}
	bool operator !() const {return is_invalid();}
	T *ptr() {return &h;}
	const T *ptr() const {return &h;}
protected:
	T h;

};
template<typename T> class pointer_raii_traits_t {
public:
	static T *null;
	static void free(T *x) {operator delete(static_cast<void *>(x));}
	using FreeFn = decltype(&free);
	using RAII = ::RAII<T *, FreeFn, &pointer_raii_traits_t<T>::free, &null>;
};

template<typename T> T *pointer_raii_traits_t<T>::null = nullptr;

static const int invalid_descriptor = -1;
using Socket = RAII<int, decltype(&close), &close, &invalid_descriptor>;
using AddrInfo = RAII<addrinfo *, decltype(&freeaddrinfo), &freeaddrinfo, &pointer_raii_traits_t<addrinfo>::null>;


static Socket open_port(const std::string_view &portdef) {
	auto splt = portdef.find(':');
	std::string addr (portdef.substr(0,splt));
	std::string port (portdef.substr(splt+1));

	Socket sock = socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP);
	if (!sock) throw ErrNoException("socket failed");

	int flag = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(int)) < 0)
		throw ErrNoException("setsockopt(SO_REUSEADDR) failed");

	AddrInfo addrinfo;
	if (getaddrinfo(addr.c_str(), port.c_str(),nullptr, addrinfo.ptr())) {
		close(sock);
		throw ErrNoException("getaddrinfo failed");
	}
	if (bind(sock,addrinfo->ai_addr, addrinfo->ai_addrlen)) {
		throw ErrNoException("tcp bind failed");
	}
	if (listen(sock,SOMAXCONN)) {
		throw ErrNoException("tcp listen failed");
	}
	if (setsockopt(sock,IPPROTO_TCP,TCP_NODELAY,(char *) &flag,sizeof(int))) {
		throw ErrNoException("setsockopt failed");
	}
	return sock;
}

class Conn {
public:
	Conn(Socket &&sock);
	std::string_view read();
	void put_back(const std::string_view &buff);
	bool read_line(std::string &ln);
	const Socket &get_socket() const {return sock;}
	void write(const std::string_view &data);

protected:
	Socket sock;
	char buffer[4096];
	std::string_view put_back_buff;
};

Conn::Conn(Socket &&sock):sock(std::move(sock)) {}

std::string_view Conn::read() {
	if (!put_back_buff.empty()) {
		auto tmp = put_back_buff;
		put_back_buff = std::string_view();
		return tmp;
	} else {
		int r = recv(sock,reinterpret_cast<unsigned char *>(buffer),sizeof(buffer),0);
		std::string_view out(buffer, r);
		return out;
	}
}
void Conn::put_back(const std::string_view &buff) {
	put_back_buff = buff;
}

bool Conn::read_line(std::string &ln) {
	ln.clear();
	std::size_t nwln;
	std::string_view data;
	do {
		data = read();
		if (data.empty()) return false;
		auto startpos = ln.length();
		if (startpos) startpos--;
		ln.append(data);
		nwln = ln.find("\r\n",startpos);
	} while (nwln == ln.npos);
	auto remain = data.substr(data.length()-(ln.length() - nwln - 2));
	put_back(remain);
	ln.resize(nwln);
	return true;
}

void Conn::write(const std::string_view &data) {
	int r = send(sock, reinterpret_cast<const unsigned char *>(data.data()), data.length(), 0);
	if (r < 1) return;
	auto more_data = data.substr(r);
	if (!more_data.empty()) write(more_data);
}

class SplitString {
public:
	SplitString(const std::string_view &text, const std::string_view &sep, std::size_t limit):text(text),sep(sep),limit(limit) {}
	bool operator!() const {return reached_end;}
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
	SplitString &operator()(std::string_view &res) {res = operator()();return *this;}
protected:
	std::string_view text;
	std::string_view sep;
	std::size_t limit;
	bool reached_end = false;
};

class Server {
public:

	Server(Socket &&s, const std::string &docroot);
	void run();


protected:
	Conn conn;
	const std::string &docroot;
	std::string hdrln;
	std::string ln;
	std::string tmpln;
	std::string tmpln2;
	std::string outbuff;
	bool run_1cycle();

	template<typename Iterable>
	void send_response(int code, const std::string_view &message, std::string_view &httpver, Iterable &&beg, Iterable &&end, bool closeconn=false);

	using InlineHeaders = std::initializer_list<TextPair>;
	void send_response(int code, const std::string_view &message, std::string_view &httpver, InlineHeaders hdrs, bool closeconn=false) {
		send_response(code,message, httpver, hdrs.begin(), hdrs.end(), closeconn);
	}
	void send_error(int code, const std::string_view &message, std::string_view &httpver);

	std::string map_uri_to_path(const std::string_view &uri, const std::string_view &index);
	template<typename T> static void number_to_string(T number, std::string &out, bool level2 = false);

	static std::string_view determine_content_type(const std::string_view &fpath);

private:
};

Server::Server(Socket &&s, const std::string &docroot)
	:conn(std::move(s))
	,docroot(docroot) {}

void Server::run() {
	while (run_1cycle());
}

bool Server::run_1cycle(){
	if (!conn.read_line(hdrln)) return false;

	std::string_view cmd, uri, proto;
	SplitString(hdrln," ",3)(cmd)(uri)(proto);
	if (cmd != "GET") {
		send_error(405,"Method Not Allowed",proto);
		return false;
	}

	try {

		if (!conn.read_line(ln)) return false;
		while (!ln.empty()) {
			if (!conn.read_line(ln)) return false;
		}


		auto fpath = map_uri_to_path(uri,"index.html");

		std::string_view content_type = determine_content_type(fpath);

		struct stat stbuf;
		if (stat(fpath.c_str(), &stbuf)) {
			throw ErrNoException("stat file failed");
		}

		if (S_ISDIR(stbuf.st_mode)) {
			tmpln = uri;
			tmpln.append("/");
			send_response(301,"Permanent redirect", proto, {
					{"Location",tmpln}
					});
		} else if (S_ISREG(stbuf.st_mode)) {

			std::size_t size = stbuf.st_size;

			//faster then std::ostringstream
			tmpln.clear();
			number_to_string(size,tmpln);

			using PosixFile = RAII<int, decltype(&close), &close, &invalid_descriptor>;
			PosixFile f = ::open(fpath.c_str(),O_RDONLY);
			if (!f) {
				throw ErrNoException("open failed");
			}

			send_response(200,"OK",proto,{
				{"Content-Type", content_type},
				{"Content-Length", tmpln}
			});

			while (size) {
				auto r = sendfile(conn.get_socket(), f, nullptr, size);
				if (r <1) size = 0; else size-=r;
			}
		}
		return true;

	} catch (std::exception &e) {
		log("Exception: ", e.what());
		send_error(404,"Not found",proto);
		return false;
	}
}

template<typename Iterable>
inline void Server::send_response(int code, const std::string_view& message,
		std::string_view& httpver, Iterable&& beg, Iterable&& end,
		bool closeconn) {

	//not using ostringstring to reuse preallocated outbuff for keep-alive connection

	outbuff.clear();
	outbuff.append(httpver).append(" ");
	number_to_string(code, outbuff);
	outbuff.append(" ").append(message).append("\r\n");
	Iterable x = beg;
	while (x != end) {
		outbuff.append(x->first).append(": ").append(x->second).append("\r\n");
		++x;
	}
	if (closeconn) {
		outbuff.append("Connection: close\r\n");
	}
	outbuff.append("\r\n");

	conn.write(outbuff);

	log(hdrln, "(",code,")");
}

inline void Server::send_error(int code, const std::string_view& message, std::string_view& httpver) {
	send_response(code, message, httpver, {
			{ "Content-Type",TEXT_HTML_CHARSET_UTF_8 },
			{"Allow","GET"}},true);

	std::ostringstream output;
	output << "<html><body><h1>" << code << " " << message << "</h1>"
			<< "<hr><small><em>Powered by minihttp server written by <a href=\"https://github.com/ondra-novak/\">Ondrej Novak</a></em></small>"
			<< "</body></html>";
	conn.write(output.str());
}

std::string Server::map_uri_to_path(const std::string_view& uri, const std::string_view& index) {

	tmpln.clear();
	SplitString splt(uri,"/",(std::size_t)-1);
	//skip anything before /
	splt();
	bool isdir = false;
	while (!!splt) {
		auto itm = splt();
		isdir = false;
		if (itm.empty()) {
			isdir = true;
		} else if (itm == ".") {
			continue;
		} else if (itm == "..") {
			auto pos = tmpln.rfind("/");
			if (pos == tmpln.npos) pos = 0;
			tmpln.resize(pos);
		} else {
			tmpln.push_back('/');
			tmpln.append(itm);
		}
	}
	if (isdir) {
		tmpln.push_back('/');
		tmpln.append(index);
	}

	return docroot + tmpln;
}

template<typename T>
inline void Server::number_to_string(T number, std::string& out, bool level2) {
	if (number < static_cast<T>(1)) {
		if (!level2) out.push_back('0');
	} else {
		number_to_string(number/10, out, true);
		out.push_back('0' + static_cast<char>((number % 10)));
	}
}

inline std::string_view Server::determine_content_type(const std::string_view& fpath) {
	auto pos = fpath.rfind('.');
	if (pos == fpath.npos)
		return APPLICATION_OCTET_STREAM;
	auto ext = fpath.substr(pos+1);
	auto iter = std::lower_bound(std::begin(mime_types), std::end(mime_types),TextPair(ext,""));
	if (iter == std::end(mime_types) || iter->first != ext)
		return APPLICATION_OCTET_STREAM;
	return iter->second;
}

static int signal_shut_socket;
static bool signal_shut_socket_signaled=false;
static void signal_handler(int sig) {
	signal_shut_socket_signaled = true;
	shutdown(signal_shut_socket, SHUT_RD);
}
static std::atomic<unsigned int> thread_counter(0);
thread_local unsigned int cur_thread_id = 0;

class LogObject {
public:
	LogObject(std::ostream &out):out(out) {}

	template<typename ... Args>
	void send_log(Args && ... args) {
		std::lock_guard<std::mutex> _(lk);
		time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
		out << std::put_time(std::localtime(&now), "%Y-%m-%d %X");
		out << " [" << cur_thread_id << "] ";
		send_log_lk(std::forward<Args>(args)...);
		out << std::endl;
	}



protected:
	std::mutex lk;
	std::ostream &out;

	template<typename T, typename ... Args>
	void send_log_lk(T &&x, Args && ... args) {
		out << x;
		send_log_lk(std::forward<Args>(args)...);
	}

	void send_log_lk() {}

};

static  LogObject *globalLogObject;

template<typename ... Args>
void log(Args && ... args) {
	globalLogObject->send_log(std::forward<Args>(args)...);
}


int main(int argc, char **argv) {

	LogObject lg(std::cout);
	globalLogObject = &lg;

	try {
		if (argc != 3) {
			std::cerr << "Invalid arguments" << std::endl
					  << std::endl
					  << "Usage: " << argv[0] << " <addr:port> <path_to_document_root>" << std::endl;
			return 1;
		}

		Socket sock;

		std::string_view port(argv[1]);
		if (port.find(':') != port.npos) {
			sock = open_port(port);
		} else  {
			std::cerr << "First argument must be <addr:port>"<<std::endl
					 <<std::endl
					 <<"127.0.0.1:12345   - open port 12345 on localhost"<<std::endl
					 <<"10.0.10.95:12345   - open port 12345 on specified interface"<<std::endl
					 <<":12345   - open port 12345 on all interfaces"<<std::endl;
			return 1;
		}

		std::string docroot(argv[2]);

		signal_shut_socket = sock;
		std::signal(SIGPIPE,SIG_IGN);
		std::signal(SIGCHLD,SIG_IGN);
		std::signal(SIGQUIT,&signal_handler);
		std::signal(SIGTERM,&signal_handler);
		std::signal(SIGINT,&signal_handler);
		std::signal(SIGHUP,&signal_handler);

		log("Server ready");

		for(;;) {
			Socket s (accept(sock, nullptr, 0));
			if (!s) {
				if (signal_shut_socket_signaled) break;
				throw ErrNoException("accept failed");
			}

			std::thread thr([s = Socket(std::move(s)), &docroot] ()mutable {
				Server srv(std::move(s), docroot);
				cur_thread_id = ++thread_counter;
				log("New connection");
				srv.run();
				log("Connection closed");
			});
			thr.detach();

		}

		log("Server exit");
		return 0;
	} catch (std::exception &e) {
		std::cerr << "ERROR:" << e.what() << std::endl;
		return 120;
	}
}

