# MicroFtp

FTP client for microcontrollers with MbedTLS support.

#### Features

- Download or Upload a file with an FTP URL
- FTP over TLS (FTPS) as described in [RFC 4217](https://datatracker.ietf.org/doc/html/rfc4217)
- Callback-driven file transfer, cooperative multitasking friendly

The main use cases of this FTP client are firmware updates (typical download size 1MB) and log file uploads (typical upload size 100kB).

#### Compatible FTP servers

Currently, the compatibility with the following FTP servers has been tested:

| Server | FTP | FTPS |
| --- | --- | --- |
| [vsftp](https://security.appspot.com/vsftpd.html) |  | ✔️ |
| [Rebex](https://www.rebex.net/) | ✔️ | ✔️ |
| [Windows Server 2022](https://www.microsoft.com/en-us/windows-server) | ✔️ | ✔️ |
| [SFTPGo](https://github.com/drakkan/sftpgo) | ✔️ | |

#### Usage

Download a file using the C++ API:

```cpp
MicroFtp::FtpClient ftp;

ftp.getFile("ftps://user:pass@ftp.example.com/dir/firmware.bin",
        [] (unsigned char *data, size_t len) -> size_t {
            //write firmware data on flash
            return len;
        }, [] () {
            //finalize OTA update
        });

for (;;) {
    ftp.loop(); //add to main-loop
}
```

Upload a file using the C++ API:

```cpp
MicroFtp::FtpClient ftp;

ftp.postFile("ftps://user:pass@ftp.example.com/dir/log.txt",
        [] (unsigned char *data, size_t len) -> size_t {
            //write log file contents to `data` having length `len`
            return /* written */; //return number of bytes actually written to `data` (0 to finish upload)
        }, [] () {
            //connection close callback
        });

for (;;) {
    ftp.loop(); //add to main-loop
}
```

To compile the sources, ensure that MbedTLS (v2.28.1) is on the include path. On Ubuntu, MbedTLS needs to be downloaded manually into `lib/mbedtls`. There are no more dependencies. The CMakeLists file will add a default integration for different toolchains in future (at the moment it's only useful for building the compatibility tester).

#### Checking FTP server compatibility

To test the compatibility with different servers, you can build and run the program in the `test` folder. In the root directory of this project, generate the build files:

```shell
cmake -S . -B ./build
```

Build the project:

```shell
cmake --build ./build --target microftp_test -j 16
```

Execute the tester with the `download_url` or `upload_url` param, containing an FTP URL:

```shell
./build/microftp_test --download_url=ftps://demo:password@test.rebex.net/pub/example/readme.txt
```

The log will show lots of (partially unimportant) messages. The file transfer was successful if you can find the message code `226` somewhere at the end.

If you encounter compatibility problems, please open an issue. If the client works well with a server not in the list already, feel free to report it!

#### Release time frame

Development of this code started in March 2023 (it was maintained in a [different repo](https://github.com/matth-x/MicroOcppMongoose)). Release is planned for July 2024, if no severe issues start popping up in the meantime.

Until then, more platform integrations will be added and still, more testing needs to be done to reach final production-readiness.
