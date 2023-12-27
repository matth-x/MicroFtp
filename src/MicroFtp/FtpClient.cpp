// matth-x/MicroFtp
// Copyright Matthias Akstaller 2023
// MIT License

#include "MicroFtp/FtpClient.h"

#include <cstring>

#include "mbedtls/error.h"

/*
 * Logging-related functions / macros
 */

namespace MicroFtp {
void (*log_fn)(int level, const char *fn, int line, const char *msg) = nullptr;
void log(int level, const char *fn, int line, const char *msg) {
    if (level > MF_DBG_LEVEL) {
        //return;
    }
    if (log_fn) {
        log_fn(level, fn, line, msg);
    }
}

void log_mbedtls(void *user, int level, const char *file, int line, const char *str) {
    log(level, "mbedtls", line, str);
}
}

using namespace MicroFtp;

void MicroFtp::set_log_fn(void (*log)(int level, const char *fn, int line, const char *msg)) {
    log_fn = log;
}

#ifndef MF_LOG_MAXMSGSIZE
#define MF_LOG_MAXMSGSIZE 192
#endif

#define MF_LOG(LEVEL, X, ...) \
    do { \
        char _mf_msg [MF_LOG_MAXMSGSIZE]; \
        auto _mf_ret = snprintf(_mf_msg, MF_LOG_MAXMSGSIZE, X, ##__VA_ARGS__); \
        if (_mf_ret < 0 || _mf_ret >= MF_LOG_MAXMSGSIZE) { \
            sprintf(_mf_msg + MF_LOG_MAXMSGSIZE - 7, " [...]"); \
        } \
        log(LEVEL, "ftp.cpp", __LINE__, _mf_msg); \
    } while (0)

#define MF_DBG_ERR(X, ...) MF_LOG(MF_DL_ERROR, X, ##__VA_ARGS__)
#define MF_DBG_WARN(X, ...) MF_LOG(MF_DL_WARN, X, ##__VA_ARGS__)
#define MF_DBG_INFO(X, ...) MF_LOG(MF_DL_INFO, X, ##__VA_ARGS__)
#define MF_DBG_DEBUG(X, ...) MF_LOG(MF_DL_DEBUG, X, ##__VA_ARGS__)
#define MF_DBG_VERBOSE(X, ...) MF_LOG(MF_DL_VERBOSE, X, ##__VA_ARGS__)

/*
 * FTP implementation
 */

FtpClient::FtpClient(bool tls_only, const char *ca_cert, const char *client_cert, const char *client_key) 
        : isSecure(tls_only), ca_cert(ca_cert), client_cert(client_cert), client_key(client_key) {
    mbedtls_net_init(&ctrl_fd);
    mbedtls_ssl_init(&ctrl_ssl);
    mbedtls_net_init(&data_fd);
    mbedtls_ssl_init(&data_ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_x509_crt_init(&clicert);
    mbedtls_pk_init(&pkey);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
}

FtpClient::~FtpClient() {
    if (onClose) {
        onClose();
        onClose = nullptr;
    }
    delete[] data_buf;
    mbedtls_x509_crt_free(&clicert);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_pk_free(&pkey);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_net_free(&ctrl_fd);
    mbedtls_ssl_free(&ctrl_ssl);
    mbedtls_net_free(&data_fd);
    mbedtls_ssl_free(&data_ssl);
}

int FtpClient::setup_tls() {

    if (auto ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char*) __FILE__,
                                     strlen(__FILE__)) != 0) {
        MF_DBG_ERR("mbedtls_ctr_drbg_seed: %i", ret);
        return ret;
    }

    if (ca_cert) {
        if (auto ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *) ca_cert,
                                    strlen(ca_cert)) < 0) {
            MF_DBG_ERR("mbedtls_x509_crt_parse(ca_cert): %i", ret);
            return ret;
        }
    }

    if (client_cert) {
        if (auto ret = mbedtls_x509_crt_parse(&clicert, (const unsigned char *) client_cert,
                                    strlen(client_cert))) {
            MF_DBG_ERR("mbedtls_x509_crt_parse(client_cert): %i", ret);
            return ret;
        }
    }

    if (client_key) {
        if (auto ret = mbedtls_pk_parse_key(&pkey,
                                    (const unsigned char *) client_key,
                                    strlen(client_key),
                                    NULL,
                                    0)) {
            MF_DBG_ERR("mbedtls_pk_parse_key: %i", ret);
            return ret;
        }
    }

    if (auto ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        MF_DBG_ERR("mbedtls_ssl_config_defaults: %i", ret);
        return ret;
    }

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL); //certificate check result manually handled for now

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, log_mbedtls, NULL);

    if (ca_cert) {
        mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    }

    if (client_cert || client_key) {
        if (auto ret = mbedtls_ssl_conf_own_cert(&conf, &clicert, &pkey) != 0) {
            MF_DBG_ERR("mbedtls_ssl_conf_own_cert: %i", ret);
            return ret;
        }
    }

    return 0; //success
}

int FtpClient::connect(mbedtls_net_context& fd, mbedtls_ssl_context& ssl, const char *server_name, const char *server_port) {

    if (auto ret = mbedtls_net_connect(&fd, server_name, server_port, MBEDTLS_NET_PROTO_TCP) != 0) {
        MF_DBG_ERR("mbedtls_net_connect: %i", ret);
        return ret;
    }

    if (auto ret = mbedtls_net_set_nonblock(&fd)) {
        MF_DBG_ERR("mbedtls_net_set_nonblock: %i", ret);
        return ret;
    }

    if (auto ret = mbedtls_ssl_setup(&ssl, &conf) != 0) {
        MF_DBG_ERR("mbedtls_ssl_setup: %i", ret);
        return ret;
    }

    if (auto ret = mbedtls_ssl_set_hostname(&ssl, server_name) != 0) {
        MF_DBG_ERR("mbedtls_ssl_set_hostname: %i", ret);
        return ret;
    }

    mbedtls_ssl_set_bio(&ssl, &fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    return 0; //success
}

int FtpClient::connect_ctrl() {
    if (auto ret = connect(ctrl_fd, ctrl_ssl, ctrl_host.c_str(), ctrl_port.c_str())) {
        MF_DBG_ERR("connect: %i", ret);
        return ret;
    }

    ctrl_opened = true;

    //handshake will be done later during STARTTLS procedure

    return 0; //success
}

int FtpClient::connect_data() {
    if (auto ret = connect(data_fd, data_ssl, data_host.c_str(), data_port.c_str())) {
        MF_DBG_ERR("connect: %i", ret);
        return ret;
    }

    data_opened = true;

    if (isSecure) {
        //reuse SSL session of ctrl conn

        if (auto ret = mbedtls_ssl_set_session(&data_ssl, 
                    mbedtls_ssl_get_session_pointer(&ctrl_ssl))) {
            MF_DBG_ERR("session reuse failure: %i", ret);
            return ret;
        }

        data_ssl_established = true;
    }

    if (!data_buf) {
        data_buf = new unsigned char[data_buf_size];
        if (!data_buf) {
            MF_DBG_ERR("OOM");
            return -1;
        }
    }

    return 0; //success
}

void FtpClient::close_ctrl() {
    if (!ctrl_opened) {
        return;
    }

    if (ctrl_ssl_established) {
        mbedtls_ssl_close_notify(&ctrl_ssl);
        ctrl_ssl_established = false;
    }
    mbedtls_net_close(&ctrl_fd);
    ctrl_opened = false;

    if (onClose) {
        onClose();
        onClose = nullptr;
    }
}

void FtpClient::close_data() {
    if (!data_opened) {
        return;
    }

    MF_DBG_DEBUG("closing data conn");

    if (data_ssl_established) {
        MF_DBG_DEBUG("TLS shutdown");
        mbedtls_ssl_close_notify(&data_ssl);
        data_ssl_established = false;
    }
    mbedtls_net_close(&data_fd);
    data_opened = false;
    data_conn_accepted = false;
}

int FtpClient::handshake_tls() {

    while (auto ret = mbedtls_ssl_handshake(&ctrl_ssl) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret != 1) {
            char buf [1024];
            mbedtls_strerror(ret, (char *) buf, 1024);
            MF_DBG_ERR("mbedtls_ssl_handshake: %i, %s", ret, buf);
            return ret;
        }
    }

    if (ca_cert) {
        //certificate validation enabled

        if (auto ret = mbedtls_ssl_get_verify_result(&ctrl_ssl) != 0) {
            char vrfy_buf[512];
            mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "   > ", ret);
            MF_DBG_ERR("mbedtls_ssl_get_verify_result: %i, %s", ret, vrfy_buf);
            return ret;
        }
    }

    ctrl_ssl_established = true;

    return 0; //success
}

void FtpClient::send_cmd(const char *cmd, const char *arg, bool disable_tls_policy) {

    const size_t MSG_SIZE = 128;
    unsigned char msg [MSG_SIZE];

    auto len = snprintf((char*) msg, MSG_SIZE, "%s%s%s\r\n", 
            cmd,               //cmd mandatory (e.g. "USER")
            arg ? " " : "",    //line spacing if arg is provided
            arg ? arg : "");   //arg optional (e.g. "anonymous")
    if (len < 0 || len >= MSG_SIZE) {
        MF_DBG_ERR("could not write cmd, send QUIT instead");
        len = sprintf((char*) msg, "QUIT\r\n");
    } else {
        //show outgoing traffic for debug, but shadow PASS
        MF_DBG_DEBUG("SEND: %s %s", 
                cmd,
                !strncmp((char*) cmd, "PASS", strlen("PASS")) ? "***" : arg ? (char*) arg : "");
        (void)0;
    }

    int ret = -1;

    if (ctrl_ssl_established) {
        ret = mbedtls_ssl_write(&ctrl_ssl, (unsigned char*) msg, len);
    } else if (!isSecure || disable_tls_policy) {
        ret = mbedtls_net_send(&ctrl_fd, (unsigned char*) msg, len);
    } else {
        MF_DBG_ERR("TLS policy failure");
        len = strlen("QUIT\r\n");
        ret = mbedtls_net_send(&ctrl_fd, (unsigned char*) "QUIT\r\n", len);
    }

    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
            ret <= 0 ||
            ret < (int) len) {
        char buf [1024];
        mbedtls_strerror(ret, (char *) buf, 1024);
        MF_DBG_ERR("fatal - message on ctrl channel lost: %i, %s", ret, buf);
        close_ctrl();
        return;
    }
}

bool FtpClient::getFile(const char *ftp_url_raw, std::function<size_t(unsigned char *data, size_t len)> fileWriter, std::function<void()> onClose) {
    
    if (method != Method::UNDEFINED) {
        MF_DBG_ERR("FTP Client reuse not supported");
        return false;
    }
    
    if (!ftp_url_raw || !fileWriter) {
        MF_DBG_ERR("invalid args");
        return false;
    }

    this->method = Method::Retrieve;
    this->fileWriter = fileWriter;
    this->onClose = onClose;

    if (!read_url_ctrl(ftp_url_raw)) {
        MF_DBG_ERR("could not parse URL");
        return false;
    }

    MF_DBG_DEBUG("init download from %s: %s", ctrl_host.c_str(), fname.c_str());

    if (auto ret = setup_tls()) {
        MF_DBG_ERR("could not setup MbedTLS: %i", ret);
        return false;
    }

    if (auto ret = connect_ctrl()) {
        MF_DBG_ERR("could not establish connection to FTP server: %i", ret);
        return false;
    }

    return true;
}

bool FtpClient::postFile(const char *ftp_url_raw, std::function<size_t(unsigned char *out, size_t buffsize)> fileReader, std::function<void()> onClose) {
    
    if (method != Method::UNDEFINED) {
        MF_DBG_ERR("FTP Client reuse not supported");
        return false;
    }

    if (!ftp_url_raw || !fileReader) {
        MF_DBG_ERR("invalid args");
        return false;
    }

    MF_DBG_DEBUG("init upload %s", ftp_url_raw);

    this->method = Method::Append;
    this->fileReader = fileReader;
    this->onClose = onClose;

    if (!read_url_ctrl(ftp_url_raw)) {
        MF_DBG_ERR("could not parse URL");
        return false;
    }

    if (auto ret = setup_tls()) {
        MF_DBG_ERR("could not setup MbedTLS: %i", ret);
        return false;
    }

    if (auto ret = connect_ctrl()) {
        MF_DBG_ERR("could not establish connection to FTP server: %i", ret);
        return false;
    }

    return true;
}

void FtpClient::process_ctrl() {
    // read input (if available)

    const size_t INBUF_SIZE = 128;
    unsigned char inbuf [INBUF_SIZE];
    memset(inbuf, 0, INBUF_SIZE);

    int ret = -1;

    if (ctrl_ssl_established) {
        ret = mbedtls_ssl_read(&ctrl_ssl, inbuf, INBUF_SIZE - 1);
    } else {
        ret = mbedtls_net_recv(&ctrl_fd, inbuf, INBUF_SIZE - 1);
    }

    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        //no new input data to be processed
        return;
    } else if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || ret == 0) {
        MF_DBG_ERR("FTP transfer aborted");
        close_ctrl();
        return;
    } else if (ret < 0) {
        MF_DBG_ERR("mbedtls_net_recv: %i", ret);
        send_cmd("QUIT");
        close_ctrl();
        return;
    }

    size_t inbuf_len = ret;

    // read multi-line command
    char *line_next = (char*) inbuf;
    while (line_next < (char*) inbuf + inbuf_len) {

        // take current line
        char *line = line_next;

        // null-terminate current line and find begin of next line
        while (line_next + 1 < (char*) inbuf + inbuf_len && *line_next != '\n') {
            line_next++;
        }
        *line_next = '\0';
        line_next++;

        MF_DBG_DEBUG("RECV: %s", line);

        if (isSecure && !ctrl_ssl_established) { //tls not established yet, set up according to RFC 4217
            if (!strncmp("220", line, 3)) {
                MF_DBG_DEBUG("start TLS negotiation");
                send_cmd("AUTH TLS", nullptr, true);
                return;
            } else if (!strncmp("234", line, 3)) { // Proceed with TLS negotiation
                MF_DBG_DEBUG("upgrade to TLS");

                if (auto ret = handshake_tls()) {
                    MF_DBG_ERR("handshake: %i", ret);
                    send_cmd("QUIT", nullptr, true);
                    return;
                }
            } else {
                MF_DBG_ERR("cannot proceed without TLS");
                send_cmd("QUIT", nullptr, true);
                return;
            }
        }

        if (isSecure && !ctrl_ssl_established) {
            //failure to establish security policy
            MF_DBG_ERR("internal error");
            send_cmd("QUIT", nullptr, true);
            return;
        }

        //security policy met
                
        if (!strncmp("530", line, 3)            // Not logged in
                || !strncmp("220", line, 3)     // Service ready for new user
                || !strncmp("234", line, 3)) {  // Just completed AUTH TLS handshake
            MF_DBG_DEBUG("select user %s", user.empty() ? "anonymous" : user.c_str());
            send_cmd("USER", user.empty() ? "anonymous" : user.c_str());
        } else if (!strncmp("331", line, 3)) { // User name okay, need password
            MF_DBG_DEBUG("enter pass %.2s***", pass.empty() ? "-" : pass.c_str());
            send_cmd("PASS", pass.c_str());
        } else if (!strncmp("230", line, 3)) { // User logged in, proceed
            MF_DBG_DEBUG("select directory %s", dir.empty() ? "/" : dir.c_str());
            send_cmd("CWD", dir.empty() ? "/" : dir.c_str());
        } else if (!strncmp("250", line, 3)) { // Requested file action okay, completed
            MF_DBG_VERBOSE("enter passive mode");
            if (isSecure) {
                send_cmd("PBSZ 0\r\n"
                         "PROT P\r\n" //RFC 4217: set FTP session Private
                         "PASV");
            } else {
                send_cmd("PASV");
            }
        } else if (!strncmp("227", line, 3)) { // Entering Passive Mode (h1,h2,h3,h4,p1,p2)

            if (!read_url_data(line + 3)) { //trim leading response code
                MF_DBG_ERR("could not process data url. Expect format: (h1,h2,h3,h4,p1,p2)");
                send_cmd("QUIT");
                return;
            }

            if (auto ret = connect_data()) {
                MF_DBG_ERR("data connection failure: %i", ret);
                send_cmd("QUIT");
                return;
            }

            if (method == Method::Retrieve) {
                MF_DBG_DEBUG("request download for %s", fname.c_str());
                send_cmd("RETR", fname.c_str());
            } else if (method == Method::Append) {
                MF_DBG_DEBUG("request upload for %s", fname.c_str());
                send_cmd("APPE", fname.c_str());
            } else {
                MF_DBG_ERR("internal error");
                send_cmd("QUIT");
                return;
            }

        } else if (!strncmp("150", line, 3)    // File status okay; about to open data connection
                || !strncmp("125", line, 3)) { // Data connection already open
            MF_DBG_DEBUG("data connection accepted");
            data_conn_accepted = true;
        } else if (!strncmp("226", line, 3)) { // Closing data connection. Requested file action successful (for example, file transfer or file abort)
            MF_DBG_INFO("FTP success: %s", line);
            send_cmd("QUIT");
            return;
        } else if (!strncmp("55", line, 2)) { // Requested action not taken / aborted
            MF_DBG_WARN("FTP failure: %s", line);
            send_cmd("QUIT");
            return;
        } else if (!strncmp("200", line, 3)) { //PBSZ -> 0 and PROT -> P accepted
            MF_DBG_INFO("PBSZ/PROT success: %s", line);
            (void)0;
        } else if (!strncmp("221", line, 3)) { // Server Goodbye
            MF_DBG_DEBUG("closing ctrl connection");
            close_ctrl();
            return;
        } else {
            MF_DBG_WARN("unkown commad (close connection): %s", line);
            send_cmd("QUIT");
            return;
        }
    }
}

void FtpClient::process_data() {
    if (!data_conn_accepted) {
        return;
    }

    if (isSecure && !data_ssl_established) {
        //failure to establish security policy
        MF_DBG_ERR("internal error");
        send_cmd("QUIT", nullptr, true);
        return;
    }

    if (method == Method::Retrieve) {

        if (data_buf_avail == 0) {
            //load new data from socket

            data_buf_offs = 0;

            int ret = -1;
            if (data_ssl_established) {
                ret = mbedtls_ssl_read(&data_ssl, data_buf, data_buf_size - 1);
            } else {
                ret = mbedtls_net_recv(&data_fd, data_buf, data_buf_size - 1);
            }

            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                //no new input data to be processed
                return;
            } else if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || ret == 0) {
                //download finished
                close_data();
                return;
            } else if (ret < 0) {
                MF_DBG_ERR("mbedtls_net_recv: %i", ret);
                close_data();
                return;
            }

            data_buf_avail = ret;
        }

        auto ret = fileWriter(data_buf + data_buf_offs, data_buf_avail);

        if (ret <= data_buf_avail) {
            data_buf_avail -= ret;
            data_buf_offs += ret;
        } else {
            MF_DBG_ERR("write error");
            send_cmd("QUIT");
            return;
        }

        //success
    } else if (method == Method::Append) {

        if (data_buf_avail == 0) {
            //load new data from file to write on socket

            data_buf_offs = 0;

            data_buf_avail = fileReader(data_buf, data_buf_size);
        }

        if (data_buf_avail > 0) {

            int ret = -1;
            if (data_ssl_established) {
                ret = mbedtls_ssl_write(&data_ssl, data_buf + data_buf_offs, data_buf_avail);
            } else {
                ret = mbedtls_net_send(&data_fd, data_buf + data_buf_offs, data_buf_avail);
            }

            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                //no data sent, wait
                return;
            } else if (ret <= 0) {
                MF_DBG_ERR("mbedtls_ssl_write: %i", ret);
                send_cmd("QUIT");
                return;
            }

            //successful write
            data_buf_avail -= ret;
            data_buf_offs += ret;
        } else {
            //no data in fileReader anymore
            MF_DBG_DEBUG("finished file reading");
            close_data();
        }
    }
}

void FtpClient::loop() {

    if (!ctrl_opened && data_opened) {
        MF_DBG_ERR("dangling data connection");
        close_data(); //clean connection
        return;
    }

    if (ctrl_opened) {
        process_ctrl();
    }

    if (data_opened) {
        process_data();
    }
}

bool FtpClient::read_url_ctrl(const char *ftp_url_raw) {
    std::string ftp_url = ftp_url_raw; //copy input ftp_url

    //tolower protocol specifier
    for (auto c = ftp_url.begin(); *c != ':' && c != ftp_url.end(); c++) {
        *c = tolower(*c);
    }

    //parse FTP URL: protocol specifier
    std::string proto;
    if (!strncmp(ftp_url.c_str(), "ftps://", strlen("ftps://"))) {
        //FTP over TLS (RFC 4217)
        proto = "ftps://";
        isSecure = true; //TLS policy
    } else if (!strncmp(ftp_url.c_str(), "ftp://", strlen("ftp://"))) {
        //FTP without security policies (RFC 959)
        proto = "ftp://";
    } else {
        MF_DBG_ERR("protocol not supported. Please use ftps:// or ftp://");
        return false;
    }

    //parse FTP URL: dir and fname
    auto dir_pos = ftp_url.find_first_of('/', proto.length());
    if (dir_pos != std::string::npos) {
        auto fname_pos = ftp_url.find_last_of('/');
        dir = ftp_url.substr(dir_pos, fname_pos - dir_pos);
        fname = ftp_url.substr(fname_pos + 1);
    }

    if (fname.empty()) {
        MF_DBG_ERR("missing filename");
        return false;
    }

    MF_DBG_VERBOSE("parsed dir: %s; fname: %s", dir.c_str(), fname.c_str());

    //parse FTP URL: user, pass, host, port

    std::string user_pass_host_port = ftp_url.substr(proto.length(), dir_pos - proto.length());
    std::string user_pass, host_port;
    auto user_pass_delim = user_pass_host_port.find_first_of('@');
    if (user_pass_delim != std::string::npos) {
        host_port = user_pass_host_port.substr(user_pass_delim + 1);
        user_pass = user_pass_host_port.substr(0, user_pass_delim);
    } else {
        host_port = user_pass_host_port;
    }

    if (!user_pass.empty()) {
        auto user_delim = user_pass.find_first_of(':');
        if (user_delim != std::string::npos) {
            user = user_pass.substr(0, user_delim);
            pass = user_pass.substr(user_delim + 1);
        } else {
            user = user_pass;
        }
    }

    MF_DBG_VERBOSE("parsed user: %s; pass: %.2s***", user.c_str(), pass.empty() ? "-" : pass.c_str());

    if (host_port.empty()) {
        MF_DBG_ERR("missing hostname");
        return false;
    }

    auto host_port_delim = host_port.find(':');
    if (host_port_delim != std::string::npos) {
        ctrl_host = host_port.substr(host_port_delim + 1);
        ctrl_port = host_port.substr(0, host_port_delim);
    } else {
        //use default port number
        ctrl_host = host_port;
        ctrl_port = "21";
    }

    return true;
}

bool FtpClient::read_url_data(const char *data_url_raw) {

    std::string data_url = data_url_raw; //format like " Entering Passive Mode (h1,h2,h3,h4,p1,p2)"

    // parse address field. Replace all non-digits by delimiter character ' '
    for (char& c : data_url) {
        if (c < '0' || c > '9') {
            c = (unsigned char) ' ';
        }
    }

    unsigned int h1 = 0, h2 = 0, h3 = 0, h4 = 0, p1 = 0, p2 = 0;

    auto ntokens = sscanf(data_url.c_str(), "%u %u %u %u %u %u", &h1, &h2, &h3, &h4, &p1, &p2);
    if (ntokens != 6) {
        MF_DBG_ERR("could not process data url. Expect format: (h1,h2,h3,h4,p1,p2)");
        return false;
    }

    unsigned int port = 256U * p1 + p2;

    char buf [64] = {'\0'};
    auto ret = snprintf(buf, 64, "%u.%u.%u.%u", h1, h2, h3, h4);
    if (ret < 0 || ret >= 64) {
        MF_DBG_ERR("data url format failure");
        return false;
    }
    data_host = buf;

    ret = snprintf(buf, 64, "%u", port);
    if (ret < 0 || ret >= 64) {
        MF_DBG_ERR("data url format failure");
        return false;
    }
    data_port = buf;

    return true;
}
