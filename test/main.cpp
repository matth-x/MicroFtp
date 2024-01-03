// matth-x/MicroFtp
// Copyright Matthias Akstaller 2023
// MIT License

/*
 * Test program to check the compatibility against FTP servers
 */

#include "MicroFtp/FtpClient.h"

#include <cstring>
#include <iostream>
#include <fstream>

#include "mbedtls/debug.h"

//set default URLs (if no args are given)
#ifndef MF_TEST_UPLOAD_URL
#define MF_TEST_UPLOAD_URL ""  //e.g. "ftps://..."
#endif

#ifndef MF_TEST_DOWNLOAD_URL
#define MF_TEST_DOWNLOAD_URL ""
#endif

#define USAGE \
    "Usage: %s [OPTION]...\n" \
    "Test the compatibility of the MicroFTP library against FTP servers\n" \
    "\n" \
    "    --upload_url=URL         Upload URL (e.g. ftps://user:pass@example.com/dir/hello_world.txt). Default: " MF_TEST_UPLOAD_URL "\n" \
    "    --download_url=URL       Download URL (e.g. ftps://user:pass@example.com/dir/hello_world.txt). Default: " MF_TEST_DOWNLOAD_URL "\n" \
    "\n",\
    argv[0]

//MicroFtp sends all debug and error messages to a user-provided callback function
void debug_fn(int level, const char *fn, int line, const char *msg) {
    const char *lstr = "";
    switch (level) {
        case MF_DL_ERROR:
            lstr = "ERROR";
            break;
        case MF_DL_WARN:
            lstr = "warn";
            break;
        case MF_DL_INFO:
            lstr = "info";
            break;
        case MF_DL_DEBUG:
            lstr = "debug";
            break;
        case MF_DL_VERBOSE:
            lstr = "verbose";
            break;
    }
    printf("[MF] %s (%s:%i): %s\n", lstr, fn, line, msg);
}

int main(int argc, char *argv[]) {

    const char *upload_url = MF_TEST_UPLOAD_URL;
    const char *download_url = MF_TEST_DOWNLOAD_URL;

    if (argc < 2 && !*upload_url && !*download_url) {
        printf(USAGE);
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        char *p, *q;
        p = argv[i];
        if ((q = strchr(p, '=')) == NULL) {
            printf(USAGE);
            return 1;
        }
        *q++ = '\0';

        if (strcmp(p, "--upload_url") == 0) {
            upload_url = q;
        } else if (strcmp(p, "--download_url") == 0) {
            download_url = q;
        } else {
            printf(USAGE);
            return 1;
        }
    }

    MicroFtp::set_log_fn(debug_fn);
    mbedtls_debug_set_threshold(1); //print MbedTLS errors

    if (*upload_url) {
        std::cout << "[main] Start FTP upload" << std::endl;

        MicroFtp::FtpClient ftp;

        bool inProgress = true;
        int uploadChunk = 0; //write file with 4 test messages
        int uploadTotal = 4;

        ftp.postFile(upload_url,
            [&uploadChunk, &uploadTotal] (unsigned char *data, size_t len) -> size_t {
                if (uploadChunk == uploadTotal) {
                    return 0; //finished
                }
                uploadChunk++;
                int written = snprintf((char*) data, len, "MicroFTP test (%i/%i)\n", uploadChunk, uploadTotal);
                printf("[main] upload chunk: %s", data);
                return written;
            }, [&inProgress] () {
                std::cout << "[main] upload -- onClose" << std::endl;
                inProgress = false;
            });
        
        while (inProgress) {
            ftp.loop();
        }

        std::cout << "[main] upload -- end" << std::endl;
    }

    if (*download_url) {
        
        std::string fn;
        std::string d_url = download_url;
        auto fn_delim = d_url.find_last_of('/');
        if (fn_delim != std::string::npos) {
            fn = d_url.substr(fn_delim + 1);
        }
        if (fn.empty()) {
            fn = "test_download.txt";
        }

        std::cout << "[main] Start FTP download (" << fn.c_str() << ")" << std::endl;

        std::ofstream file;
        file.open (fn.c_str());

        MicroFtp::FtpClient ftp;

        bool inProgress = true;
        size_t total = 0;
        size_t trackTotal = 0;

        ftp.getFile(download_url,
            [&file, &total, &trackTotal] (unsigned char *data, size_t len) -> size_t {
                file.write((const char*)data, len);
                if (total == 0) {
                    //only print first chunk
                    printf("[main] download preview: %.*s [...]\n", std::min((int) len, 64), (const char*) data);
                }
                total += len;
                if (total < 16384) {
                    printf("[main] download progress: %zu B\n", total);
                    //trackTotal = total;
                } else if (total - trackTotal >= 102400) {
                    trackTotal += 102400;
                    printf("[main] download progress: %zu kB\n", trackTotal / 1024);
                }
                return len;
            }, [&file, &inProgress] () {
                std::cout << "[main] download -- onClose" << std::endl;
                file.close();
                inProgress = false;
            });
        
        while (inProgress) {
            ftp.loop();
        }

        std::cout << "[main] download -- end. Fetched " << total << " Bytes." << std::endl;
    }
    
    return 0;
}
