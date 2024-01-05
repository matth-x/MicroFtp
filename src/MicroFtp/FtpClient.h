// matth-x/MicroFtp
// Copyright Matthias Akstaller 2023
// MIT License

#ifndef MICROFTP_CLIENT_H
#define MICROFTP_CLIENT_H

#include <string>
#include <functional>

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509.h"

namespace MicroFtp {

class FtpClient {
private:
    //MbedTLS common
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt clicert;
    mbedtls_pk_context pkey;
    const char *ca_cert = nullptr;
    const char *client_cert = nullptr;
    const char *client_key = nullptr;
    bool isSecure = false; //tls policy

    //control connection specific
    mbedtls_net_context ctrl_fd;
    mbedtls_ssl_context ctrl_ssl;
    bool ctrl_opened = false;
    bool ctrl_ssl_established = false;

    //data connection specific
    mbedtls_net_context data_fd;
    mbedtls_ssl_context data_ssl;
    bool data_opened = false;
    bool data_ssl_established = false;
    bool data_conn_accepted = false; //Server sent okay to upload / download data

    //FTP URL
    std::string user;
    std::string pass;
    std::string ctrl_host;
    std::string ctrl_port;
    std::string dir;
    std::string fname;

    std::string data_host;
    std::string data_port;

    bool read_url_ctrl(const char *ftp_url);
    bool read_url_data(const char *data_url);
    
    std::function<size_t(unsigned char *data, size_t len)> fileWriter;
    std::function<size_t(unsigned char *out, size_t bufsize)> fileReader;
    std::function<void()> onClose;

    enum class Method {
        Retrieve,  //download file
        Store,     //upload file
        UNDEFINED
    };
    Method method = Method::UNDEFINED;

    int setup_tls();
    int connect(mbedtls_net_context& fd, mbedtls_ssl_context& ssl, const char *server_name, const char *server_port);
    int connect_ctrl();
    int connect_data();
    void close_ctrl();
    void close_data();

    int handshake_tls();

    void send_cmd(const char *cmd, const char *arg = nullptr, bool disable_tls_policy = false);

    void process_ctrl();
    void process_data();

    unsigned char *data_buf = nullptr;
    size_t data_buf_size = 4096;
    size_t data_buf_avail = 0;
    size_t data_buf_offs = 0;

public:
    FtpClient(bool tls_only = false, const char *ca_cert = nullptr, const char *client_cert = nullptr, const char *client_key = nullptr);
    ~FtpClient();

    void loop();

    bool getFile(const char *ftp_url, // ftp[s]://[user[:pass]@]host[:port][/directory]/filename
            std::function<size_t(unsigned char *data, size_t len)> fileWriter,
            std::function<void()> onClose);
    
    //append file
    bool postFile(const char *ftp_url, // ftp[s]://[user[:pass]@]host[:port][/directory]/filename
            std::function<size_t(unsigned char *out, size_t buffsize)> fileReader, //write at most buffsize bytes into out-buffer. Return number of bytes written
            std::function<void()> onClose);
};

#define MF_DL_NONE 0x00     //suppress all output to the console
#define MF_DL_ERROR 0x01    //report failures
#define MF_DL_WARN 0x02     //report observed or assumed inconsistent state
#define MF_DL_INFO 0x03     //inform about internal state changes
#define MF_DL_DEBUG 0x04    //relevant info for debugging
#define MF_DL_VERBOSE 0x05  //all output

#ifndef MF_DBG_LEVEL
#define MF_DBG_LEVEL MF_DL_DEBUG  //default
#endif

void set_log_fn(void (*log)(int level, const char *fn, int line, const char *msg));

} //end namespace MicroFtp

#endif
