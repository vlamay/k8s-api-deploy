//
//  httplib.h
//
//  Copyright (c) 2025 Yuji Hirose. All rights reserved.
//  MIT License
//

#ifndef CPPHTTPLIB_HTTPLIB_H
#define CPPHTTPLIB_HTTPLIB_H

#define CPPHTTPLIB_VERSION "0.23.0"

/*
 * Platform compatibility check
 */

#if defined(_WIN32) && !defined(_WIN64)
#error                                                                         \
    "cpp-httplib doesn't support 32-bit Windows. Please use a 64-bit compiler."
#elif defined(__SIZEOF_POINTER__) && __SIZEOF_POINTER__ < 8
#error                                                                         \
    "cpp-httplib doesn't support 32-bit platforms. Please use a 64-bit compiler.
"
#elif defined(__SIZEOF_SIZE_T__) && __SIZEOF_SIZE_T__ < 8
#error                                                                         \
    "cpp-httplib doesn't support platforms where size_t is less than 64 bits."
#endif

#ifdef _WIN32
#if defined(_WIN32_WINNT) && _WIN32_WINNT < 0x0602
#error                                                                         \
    "cpp-httplib doesn't support Windows 8 or lower. Please use Windows 10 or la
ter."
#endif
#endif

/*
 * Configuration
 */

#ifndef CPPHTTPLIB_KEEPALIVE_TIMEOUT_SECOND
#define CPPHTTPLIB_KEEPALIVE_TIMEOUT_SECOND 5
#endif

#ifndef CPPHTTPLIB_KEEPALIVE_TIMEOUT_CHECK_INTERVAL_USECOND
#define CPPHTTPLIB_KEEPALIVE_TIMEOUT_CHECK_INTERVAL_USECOND 10000
#endif

#ifndef CPPHTTPLIB_KEEPALIVE_MAX_COUNT
#define CPPHTTPLIB_KEEPALIVE_MAX_COUNT 100
#endif

#ifndef CPPHTTPLIB_CONNECTION_TIMEOUT_SECOND
#define CPPHTTPLIB_CONNECTION_TIMEOUT_SECOND 300
#endif

#ifndef CPPHTTPLIB_CONNECTION_TIMEOUT_USECOND
#define CPPHTTPLIB_CONNECTION_TIMEOUT_USECOND 0
#endif

#ifndef CPPHTTPLIB_SERVER_READ_TIMEOUT_SECOND
#define CPPHTTPLIB_SERVER_READ_TIMEOUT_SECOND 5
#endif

#ifndef CPPHTTPLIB_SERVER_READ_TIMEOUT_USECOND
#define CPPHTTPLIB_SERVER_READ_TIMEOUT_USECOND 0
#endif

#ifndef CPPHTTPLIB_SERVER_WRITE_TIMEOUT_SECOND
#define CPPHTTPLIB_SERVER_WRITE_TIMEOUT_SECOND 5
#endif

#ifndef CPPHTTPLIB_SERVER_WRITE_TIMEOUT_USECOND
#define CPPHTTPLIB_SERVER_WRITE_TIMEOUT_USECOND 0
#endif

#ifndef CPPHTTPLIB_CLIENT_READ_TIMEOUT_SECOND
#define CPPHTTPLIB_CLIENT_READ_TIMEOUT_SECOND 300
#endif

#ifndef CPPHTTPLIB_CLIENT_READ_TIMEOUT_USECOND
#define CPPHTTPLIB_CLIENT_READ_TIMEOUT_USECOND 0
#endif

#ifndef CPPHTTPLIB_CLIENT_WRITE_TIMEOUT_SECOND
#define CPPHTTPLIB_CLIENT_WRITE_TIMEOUT_SECOND 5
#endif

#ifndef CPPHTTPLIB_CLIENT_WRITE_TIMEOUT_USECOND
#define CPPHTTPLIB_CLIENT_WRITE_TIMEOUT_USECOND 0
#endif

#ifndef CPPHTTPLIB_CLIENT_MAX_TIMEOUT_MSECOND
#define CPPHTTPLIB_CLIENT_MAX_TIMEOUT_MSECOND 0
#endif

#ifndef CPPHTTPLIB_IDLE_INTERVAL_SECOND
#define CPPHTTPLIB_IDLE_INTERVAL_SECOND 0
#endif

#ifndef CPPHTTPLIB_IDLE_INTERVAL_USECOND
#ifdef _WIN64
#define CPPHTTPLIB_IDLE_INTERVAL_USECOND 1000
#else
#define CPPHTTPLIB_IDLE_INTERVAL_USECOND 0
#endif
#endif

#ifndef CPPHTTPLIB_REQUEST_URI_MAX_LENGTH
#define CPPHTTPLIB_REQUEST_URI_MAX_LENGTH 8192
#endif

#ifndef CPPHTTPLIB_HEADER_MAX_LENGTH
#define CPPHTTPLIB_HEADER_MAX_LENGTH 8192
#endif

#ifndef CPPHTTPLIB_HEADER_MAX_COUNT
#define CPPHTTPLIB_HEADER_MAX_COUNT 100
#endif

#ifndef CPPHTTPLIB_REDIRECT_MAX_COUNT
#define CPPHTTPLIB_REDIRECT_MAX_COUNT 20
#endif

#ifndef CPPHTTPLIB_MULTIPART_FORM_DATA_FILE_MAX_COUNT
#define CPPHTTPLIB_MULTIPART_FORM_DATA_FILE_MAX_COUNT 1024
#endif

#ifndef CPPHTTPLIB_PAYLOAD_MAX_LENGTH
#define CPPHTTPLIB_PAYLOAD_MAX_LENGTH ((std::numeric_limits<size_t>::max)())
#endif

#ifndef CPPHTTPLIB_FORM_URL_ENCODED_PAYLOAD_MAX_LENGTH
#define CPPHTTPLIB_FORM_URL_ENCODED_PAYLOAD_MAX_LENGTH 8192
#endif

#ifndef CPPHTTPLIB_RANGE_MAX_COUNT
#define CPPHTTPLIB_RANGE_MAX_COUNT 1024
#endif

#ifndef CPPHTTPLIB_TCP_NODELAY
#define CPPHTTPLIB_TCP_NODELAY false
#endif

#ifndef CPPHTTPLIB_IPV6_V6ONLY
#define CPPHTTPLIB_IPV6_V6ONLY false
#endif

#ifndef CPPHTTPLIB_RECV_BUFSIZ
#define CPPHTTPLIB_RECV_BUFSIZ size_t(16384u)
#endif

#ifndef CPPHTTPLIB_SEND_BUFSIZ
#define CPPHTTPLIB_SEND_BUFSIZ size_t(16384u)
#endif

#ifndef CPPHTTPLIB_COMPRESSION_BUFSIZ
#define CPPHTTPLIB_COMPRESSION_BUFSIZ size_t(16384u)
#endif

#ifndef CPPHTTPLIB_THREAD_POOL_COUNT
#define CPPHTTPLIB_THREAD_POOL_COUNT                                           \
  ((std::max)(8u, std::thread::hardware_concurrency() > 0                      \
                      ? std::thread::hardware_concurrency() - 1                \
                      : 0))
#endif

#ifndef CPPHTTPLIB_RECV_FLAGS
#define CPPHTTPLIB_RECV_FLAGS 0
#endif

#ifndef CPPHTTPLIB_SEND_FLAGS
#define CPPHTTPLIB_SEND_FLAGS 0
#endif

#ifndef CPPHTTPLIB_LISTEN_BACKLOG
#define CPPHTTPLIB_LISTEN_BACKLOG 5
#endif

#ifndef CPPHTTPLIB_MAX_LINE_LENGTH
#define CPPHTTPLIB_MAX_LINE_LENGTH 32768
#endif

/*
 * Headers
 */

#ifdef _WIN64
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif //_CRT_SECURE_NO_WARNINGS

#ifndef _CRT_NONSTDC_NO_DEPRECATE
#define _CRT_NONSTDC_NO_DEPRECATE
#endif //_CRT_NONSTDC_NO_DEPRECATE

#if defined(_MSC_VER)
#if _MSC_VER < 1900
#error Sorry, Visual Studio versions prior to 2015 are not supported
#endif

#pragma comment(lib, "ws2_32.lib")

using ssize_t = __int64;
#endif // _MSC_VER

#ifndef S_ISREG
#define S_ISREG(m) (((m) & S_IFREG) == S_IFREG)
#endif // S_ISREG

#ifndef S_ISDIR
#define S_ISDIR(m) (((m) & S_IFDIR) == S_IFDIR)
#endif // S_ISDIR

#ifndef NOMINMAX
#define NOMINMAX
#endif // NOMINMAX

#include <io.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#if defined(__has_include)
#if __has_include(<afunix.h>)
// afunix.h uses types declared in winsock2.h, so has to be included after it.
#include <afunix.h>
#define CPPHTTPLIB_HAVE_AFUNIX_H 1
#endif
#endif

#ifndef WSA_FLAG_NO_HANDLE_INHERIT
#define WSA_FLAG_NO_HANDLE_INHERIT 0x80
#endif

using nfds_t = unsigned long;
using socket_t = SOCKET;
using socklen_t = int;

#else // not _WIN64

#include <arpa/inet.h>
#if !defined(_AIX) && !defined(__MVS__)
#include <ifaddrs.h>
#endif
#ifdef __MVS__
#include <strings.h>
#ifndef NI_MAXHOST
#define NI_MAXHOST 1025
#endif
#endif
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#ifdef __linux__
#include <resolv.h>
#endif
#include <csignal>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

using socket_t = int;
#ifndef INVALID_SOCKET
#define INVALID_SOCKET (-1)
#endif
#endif //_WIN64

#if defined(__APPLE__)
#include <TargetConditionals.h>
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <cctype>
#include <climits>
#include <condition_variable>
#include <cstring>
#include <errno.h>
#include <exception>
#include <fcntl.h>
#include <functional>
#include <iomanip>
#include <iostream>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#if defined(CPPHTTPLIB_USE_NON_BLOCKING_GETADDRINFO) ||                        \
    defined(CPPHTTPLIB_USE_CERTS_FROM_MACOSX_KEYCHAIN)
#if TARGET_OS_OSX
#include <CFNetwork/CFHost.h>
#include <CoreFoundation/CoreFoundation.h>
#endif
#endif // CPPHTTPLIB_USE_NON_BLOCKING_GETADDRINFO or
       // CPPHTTPLIB_USE_CERTS_FROM_MACOSX_KEYCHAIN

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
#ifdef _WIN64
#include <wincrypt.h>

// these are defined in wincrypt.h and it breaks compilation if BoringSSL is
// used
#undef X509_NAME
#undef X509_CERT_PAIR
#undef X509_EXTENSIONS
#undef PKCS7_SIGNER_INFO

#ifdef _MSC_VER
#pragma comment(lib, "crypt32.lib")
#endif
#endif // _WIN64

#if defined(CPPHTTPLIB_USE_CERTS_FROM_MACOSX_KEYCHAIN)
#if TARGET_OS_OSX
#include <Security/Security.h>
#endif
#endif // CPPHTTPLIB_USE_NON_BLOCKING_GETADDRINFO

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#if defined(_WIN64) && defined(OPENSSL_USE_APPLINK)
#include <openssl/applink.c>
#endif

#include <iostream>
#include <sstream>

#if defined(OPENSSL_IS_BORINGSSL) || defined(LIBRESSL_VERSION_NUMBER)
#if OPENSSL_VERSION_NUMBER < 0x1010107f
#error Please use OpenSSL or a current version of BoringSSL
#endif
#define SSL_get1_peer_certificate SSL_get_peer_certificate
#elif OPENSSL_VERSION_NUMBER < 0x30000000L
#error Sorry, OpenSSL versions prior to 3.0.0 are not supported
#endif

#endif // CPPHTTPLIB_OPENSSL_SUPPORT

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
#include <zlib.h>
#endif

#ifdef CPPHTTPLIB_BROTLI_SUPPORT
#include <brotli/decode.h>
#include <brotli/encode.h>
#endif

#ifdef CPPHTTPLIB_ZSTD_SUPPORT
#include <zstd.h>
#endif

/*
 * Declaration
 */
namespace httplib {

namespace detail {

/*
 * Backport std::make_unique from C++14.
 *
 * NOTE: This code came up with the following stackoverflow post:
 * https://stackoverflow.com/questions/10149840/c-arrays-and-make-unique
 *
 */

template <class T, class... Args>
typename std::enable_if<!std::is_array<T>::value, std::unique_ptr<T>>::type
make_unique(Args &&...args) {
  return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}

template <class T>
typename std::enable_if<std::is_array<T>::value, std::unique_ptr<T>>::type
make_unique(std::size_t n) {
  typedef typename std::remove_extent<T>::type RT;
  return std::unique_ptr<T>(new RT[n]);
}

namespace case_ignore {

inline unsigned char to_lower(int c) {
  const static unsigned char table[256] = {
      0,   1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,
      15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25,  26,  27,  28,  29,
      30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,
      45,  46,  47,  48,  49,  50,  51,  52,  53,  54,  55,  56,  57,  58,  59,
      60,  61,  62,  63,  64,  97,  98,  99,  100, 101, 102, 103, 104, 105, 106,
      107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121,
      122, 91,  92,  93,  94,  95,  96,  97,  98,  99,  100, 101, 102, 103, 104,
      105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
      120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134,
      135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149,
      150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164,
      165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179,
      180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 224, 225, 226,
      227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241,
      242, 243, 244, 245, 246, 215, 248, 249, 250, 251, 252, 253, 254, 223, 224,
      225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
      240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254,
      255,
  };
  return table[(unsigned char)(char)c];
}

inline bool equal(const std::string &a, const std::string &b) {
  return a.size() == b.size() &&
         std::equal(a.begin(), a.end(), b.begin(), [](char ca, char cb) {
           return to_lower(ca) == to_lower(cb);
         });
}

struct equal_to {
  bool operator()(const std::string &a, const std::string &b) const {
    return equal(a, b);
  }
};

struct hash {
  size_t operator()(const std::string &key) const {
    return hash_core(key.data(), key.size(), 0);
  }

  size_t hash_core(const char *s, size_t l, size_t h) const {
    return (l == 0) ? h
                    : hash_core(s + 1, l - 1,
                                // Unsets the 6 high bits of h, therefore no
                                // overflow happens
                                (((std::numeric_limits<size_t>::max)() >> 6) &
                                 h * 33) ^
                                    static_cast<unsigned char>(to_lower(*s)));
  }
};

template <typename T>
using unordered_set = std::unordered_set<T, detail::case_ignore::hash,
                                         detail::case_ignore::equal_to>;

} // namespace case_ignore

// This is based on
// "http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2014/n4189".

struct scope_exit {
  explicit scope_exit(std::function<void(void)> &&f)
      : exit_function(std::move(f)), execute_on_destruction{true} {}

  scope_exit(scope_exit &&rhs) noexcept
      : exit_function(std::move(rhs.exit_function)),
        execute_on_destruction{rhs.execute_on_destruction} {
    rhs.release();
  }

  ~scope_exit() {
    if (execute_on_destruction) { this->exit_function(); }
  }

  void release() { this->execute_on_destruction = false; }

private:
  scope_exit(const scope_exit &) = delete;
  void operator=(const scope_exit &) = delete;
  scope_exit &operator=(scope_exit &&) = delete;

  std::function<void(void)> exit_function;
  bool execute_on_destruction;
};

} // namespace detail

enum SSLVerifierResponse {
  // no decision has been made, use the built-in certificate verifier
  NoDecisionMade,
  // connection certificate is verified and accepted
  CertificateAccepted,
  // connection certificate was processed but is rejected
  CertificateRejected
};

enum StatusCode {
  // Information responses
  Continue_100 = 100,
  SwitchingProtocol_101 = 101,
  Processing_102 = 102,
  EarlyHints_103 = 103,

  // Successful responses
  OK_200 = 200,
  Created_201 = 201,
  Accepted_202 = 202,
  NonAuthoritativeInformation_203 = 203,
  NoContent_204 = 204,
  ResetContent_205 = 205,
  PartialContent_206 = 206,
  MultiStatus_207 = 207,
  AlreadyReported_208 = 208,
  IMUsed_226 = 226,

  // Redirection messages
  MultipleChoices_300 = 300,
  MovedPermanently_301 = 301,
  Found_302 = 302,
  SeeOther_303 = 303,
  NotModified_304 = 304,
  UseProxy_305 = 305,
  unused_306 = 306,
  TemporaryRedirect_307 = 307,
  PermanentRedirect_308 = 308,

  // Client error responses
  BadRequest_400 = 400,
  Unauthorized_401 = 401,
  PaymentRequired_402 = 402,
  Forbidden_403 = 403,
  NotFound_404 = 404,
  MethodNotAllowed_405 = 405,
  NotAcceptable_406 = 406,
  ProxyAuthenticationRequired_407 = 407,
  RequestTimeout_408 = 408,
  Conflict_409 = 409,
  Gone_410 = 410,
  LengthRequired_411 = 411,
  PreconditionFailed_412 = 412,
  PayloadTooLarge_413 = 413,
  UriTooLong_414 = 414,
  UnsupportedMediaType_415 = 415,
  RangeNotSatisfiable_416 = 416,
  ExpectationFailed_417 = 417,
  ImATeapot_418 = 418,
  MisdirectedRequest_421 = 421,
  UnprocessableContent_422 = 422,
  Locked_423 = 423,
  FailedDependency_424 = 424,
  TooEarly_425 = 425,
  UpgradeRequired_426 = 426,
  PreconditionRequired_428 = 428,
  TooManyRequests_429 = 429,
  RequestHeaderFieldsTooLarge_431 = 431,
  UnavailableForLegalReasons_451 = 451,

  // Server error responses
  InternalServerError_500 = 500,
  NotImplemented_501 = 501,
  BadGateway_502 = 502,
  ServiceUnavailable_503 = 503,
  GatewayTimeout_504 = 504,
  HttpVersionNotSupported_505 = 505,
  VariantAlsoNegotiates_506 = 506,
  InsufficientStorage_507 = 507,
  LoopDetected_508 = 508,
  NotExtended_510 = 510,
  NetworkAuthenticationRequired_511 = 511,
};

using Headers =
    std::unordered_multimap<std::string, std::string, detail::case_ignore::hash,
                            detail::case_ignore::equal_to>;

using Params = std::multimap<std::string, std::string>;
using Match = std::smatch;

using DownloadProgress = std::function<bool(size_t current, size_t total)>;
using UploadProgress = std::function<bool(size_t current, size_t total)>;

struct Response;
using ResponseHandler = std::function<bool(const Response &response)>;

struct FormData {
  std::string name;
  std::string content;
  std::string filename;
  std::string content_type;
  Headers headers;
};

struct FormField {
  std::string name;
  std::string content;
  Headers headers;
};
using FormFields = std::multimap<std::string, FormField>;

using FormFiles = std::multimap<std::string, FormData>;

struct MultipartFormData {
  FormFields fields; // Text fields from multipart
  FormFiles files;   // Files from multipart

  // Text field access
  std::string get_field(const std::string &key, size_t id = 0) const;
  std::vector<std::string> get_fields(const std::string &key) const;
  bool has_field(const std::string &key) const;
  size_t get_field_count(const std::string &key) const;

  // File access
  FormData get_file(const std::string &key, size_t id = 0) const;
  std::vector<FormData> get_files(const std::string &key) const;
  bool has_file(const std::string &key) const;
  size_t get_file_count(const std::string &key) const;
};

struct UploadFormData {
  std::string name;
  std::string content;
  std::string filename;
  std::string content_type;
};
using UploadFormDataItems = std::vector<UploadFormData>;

class DataSink {
public:
  DataSink() : os(&sb_), sb_(*this) {}

  DataSink(const DataSink &) = delete;
  DataSink &operator=(const DataSink &) = delete;
  DataSink(DataSink &&) = delete;
  DataSink &operator=(DataSink &&) = delete;

  std::function<bool(const char *data, size_t data_len)> write;
  std::function<bool()> is_writable;
  std::function<void()> done;
  std::function<void(const Headers &trailer)> done_with_trailer;
  std::ostream os;

private:
  class data_sink_streambuf final : public std::streambuf {
  public:
    explicit data_sink_streambuf(DataSink &sink) : sink_(sink) {}

  protected:
    std::streamsize xsputn(const char *s, std::streamsize n) override {
      sink_.write(s, static_cast<size_t>(n));
      return n;
    }

  private:
    DataSink &sink_;
  };

  data_sink_streambuf sb_;
};

using ContentProvider =
    std::function<bool(size_t offset, size_t length, DataSink &sink)>;

using ContentProviderWithoutLength =
    std::function<bool(size_t offset, DataSink &sink)>;

using ContentProviderResourceReleaser = std::function<void(bool success)>;

struct FormDataProvider {
  std::string name;
  ContentProviderWithoutLength provider;
  std::string filename;
  std::string content_type;
};
using FormDataProviderItems = std::vector<FormDataProvider>;

using ContentReceiverWithProgress = std::function<bool(
    const char *data, size_t data_length, size_t offset, size_t total_length)>;

using ContentReceiver =
    std::function<bool(const char *data, size_t data_length)>;

using FormDataHeader = std::function<bool(const FormData &file)>;

class ContentReader {
public:
  using Reader = std::function<bool(ContentReceiver receiver)>;
  using FormDataReader =
      std::function<bool(FormDataHeader header, ContentReceiver receiver)>;

  ContentReader(Reader reader, FormDataReader multipart_reader)
      : reader_(std::move(reader)),
        formdata_reader_(std::move(multipart_reader)) {}

  bool operator()(FormDataHeader header, ContentReceiver receiver) const {
    return formdata_reader_(std::move(header), std::move(receiver));
  }

  bool operator()(ContentReceiver receiver) const {
    return reader_(std::move(receiver));
  }

  Reader reader_;
  FormDataReader formdata_reader_;
};

using Range = std::pair<ssize_t, ssize_t>;
using Ranges = std::vector<Range>;

struct Request {
  std::string method;
  std::string path;
  std::string matched_route;
  Params params;
  Headers headers;
  Headers trailers;
  std::string body;

  std::string remote_addr;
  int remote_port = -1;
  std::string local_addr;
  int local_port = -1;

  // for server
  std::string version;
  std::string target;
  MultipartFormData form;
  Ranges ranges;
  Match matches;
  std::unordered_map<std::string, std::string> path_params;
  std::function<bool()> is_connection_closed = []() { return true; };

  // for client
  std::vector<std::string> accept_content_types;
  ResponseHandler response_handler;
  ContentReceiverWithProgress content_receiver;
  DownloadProgress download_progress;
  UploadProgress upload_progress;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  const SSL *ssl = nullptr;
#endif

  bool has_header(const std::string &key) const;
  std::string get_header_value(const std::string &key, const char *def = "",
                               size_t id = 0) const;
  size_t get_header_value_u64(const std::string &key, size_t def = 0,
                              size_t id = 0) const;
  size_t get_header_value_count(const std::string &key) const;
  void set_header(const std::string &key, const std::string &val);

  bool has_trailer(const std::string &key) const;
  std::string get_trailer_value(const std::string &key, size_t id = 0) const;
  size_t get_trailer_value_count(const std::string &key) const;

  bool has_param(const std::string &key) const;
  std::string get_param_value(const std::string &key, size_t id = 0) const;
  size_t get_param_value_count(const std::string &key) const;

  bool is_multipart_form_data() const;

  // private members...
  size_t redirect_count_ = CPPHTTPLIB_REDIRECT_MAX_COUNT;
  size_t content_length_ = 0;
  ContentProvider content_provider_;
  bool is_chunked_content_provider_ = false;
  size_t authorization_count_ = 0;
  std::chrono::time_point<std::chrono::steady_clock> start_time_ =
      (std::chrono::steady_clock::time_point::min)();
};

struct Response {
  std::string version;
  int status = -1;
  std::string reason;
  Headers headers;
  Headers trailers;
  std::string body;
  std::string location; // Redirect location

  bool has_header(const std::string &key) const;
  std::string get_header_value(const std::string &key, const char *def = "",
                               size_t id = 0) const;
  size_t get_header_value_u64(const std::string &key, size_t def = 0,
                              size_t id = 0) const;
  size_t get_header_value_count(const std::string &key) const;
  void set_header(const std::string &key, const std::string &val);

  bool has_trailer(const std::string &key) const;
  std::string get_trailer_value(const std::string &key, size_t id = 0) const;
  size_t get_trailer_value_count(const std::string &key) const;

  void set_redirect(const std::string &url, int status = StatusCode::Found_302);
  void set_content(const char *s, size_t n, const std::string &content_type);
  void set_content(const std::string &s, const std::string &content_type);
  void set_content(std::string &&s, const std::string &content_type);

  void set_content_provider(
      size_t length, const std::string &content_type, ContentProvider provider,
      ContentProviderResourceReleaser resource_releaser = nullptr);

  void set_content_provider(
      const std::string &content_type, ContentProviderWithoutLength provider,
      ContentProviderResourceReleaser resource_releaser = nullptr);

  void set_chunked_content_provider(
      const std::string &content_type, ContentProviderWithoutLength provider,
      ContentProviderResourceReleaser resource_releaser = nullptr);

  void set_file_content(const std::string &path,
                        const std::string &content_type);
  void set_file_content(const std::string &path);

  Response() = default;
  Response(const Response &) = default;
  Response &operator=(const Response &) = default;
  Response(Response &&) = default;
  Response &operator=(Response &&) = default;
  ~Response() {
    if (content_provider_resource_releaser_) {
      content_provider_resource_releaser_(content_provider_success_);
    }
  }

  // private members...
  size_t content_length_ = 0;
  ContentProvider content_provider_;
  ContentProviderResourceReleaser content_provider_resource_releaser_;
  bool is_chunked_content_provider_ = false;
  bool content_provider_success_ = false;
  std::string file_content_path_;
  std::string file_content_content_type_;
};

class Stream {
public:
  virtual ~Stream() = default;

  virtual bool is_readable() const = 0;
  virtual bool wait_readable() const = 0;
  virtual bool wait_writable() const = 0;

  virtual ssize_t read(char *ptr, size_t size) = 0;
  virtual ssize_t write(const char *ptr, size_t size) = 0;
  virtual void get_remote_ip_and_port(std::string &ip, int &port) const = 0;
  virtual void get_local_ip_and_port(std::string &ip, int &port) const = 0;
  virtual socket_t socket() const = 0;

  virtual time_t duration() const = 0;

  ssize_t write(const char *ptr);
  ssize_t write(const std::string &s);
};

class TaskQueue {
public:
  TaskQueue() = default;
  virtual ~TaskQueue() = default;

  virtual bool enqueue(std::function<void()> fn) = 0;
  virtual void shutdown() = 0;

  virtual void on_idle() {}
};

class ThreadPool final : public TaskQueue {
public:
  explicit ThreadPool(size_t n, size_t mqr = 0)
      : shutdown_(false), max_queued_requests_(mqr) {
    while (n) {
      threads_.emplace_back(worker(*this));
      n--;
    }
  }

  ThreadPool(const ThreadPool &) = delete;
  ~ThreadPool() override = default;

  bool enqueue(std::function<void()> fn) override {
    {
      std::unique_lock<std::mutex> lock(mutex_);
      if (max_queued_requests_ > 0 && jobs_.size() >= max_queued_requests_) {
        return false;
      }
      jobs_.push_back(std::move(fn));
    }

    cond_.notify_one();
    return true;
  }

  void shutdown() override {
    // Stop all worker threads...
    {
      std::unique_lock<std::mutex> lock(mutex_);
      shutdown_ = true;
    }

    cond_.notify_all();

    // Join...
    for (auto &t : threads_) {
      t.join();
    }
  }

private:
  struct worker {
    explicit worker(ThreadPool &pool) : pool_(pool) {}

    void operator()() {
      for (;;) {
        std::function<void()> fn;
        {
          std::unique_lock<std::mutex> lock(pool_.mutex_);

          pool_.cond_.wait(
              lock, [&] { return !pool_.jobs_.empty() || pool_.shutdown_; });

          if (pool_.shutdown_ && pool_.jobs_.empty()) { break; }

          fn = pool_.jobs_.front();
          pool_.jobs_.pop_front();
        }

        assert(true == static_cast<bool>(fn));
        fn();
      }

#if defined(CPPHTTPLIB_OPENSSL_SUPPORT) && !defined(OPENSSL_IS_BORINGSSL) &&   \
    !defined(LIBRESSL_VERSION_NUMBER)
      OPENSSL_thread_stop();
#endif
    }

    ThreadPool &pool_;
  };
  friend struct worker;

  std::vector<std::thread> threads_;
  std::list<std::function<void()>> jobs_;

  bool shutdown_;
  size_t max_queued_requests_ = 0;

  std::condition_variable cond_;
  std::mutex mutex_;
};

using Logger = std::function<void(const Request &, const Response &)>;

using SocketOptions = std::function<void(socket_t sock)>;

namespace detail {

bool set_socket_opt_impl(socket_t sock, int level, int optname,
                         const void *optval, socklen_t optlen);
bool set_socket_opt(socket_t sock, int level, int optname, int opt);
bool set_socket_opt_time(socket_t sock, int level, int optname, time_t sec,
                         time_t usec);

} // namespace detail

void default_socket_options(socket_t sock);

const char *status_message(int status);

std::string get_bearer_token_auth(const Request &req);

namespace detail {

class MatcherBase {
public:
  MatcherBase(std::string pattern) : pattern_(pattern) {}
  virtual ~MatcherBase() = default;

  const std::string &pattern() const { return pattern_; }

  // Match request path and populate its matches and
  virtual bool match(Request &request) const = 0;

private:
  std::string pattern_;
};

/**
 * Captures parameters in request path and stores them in Request::path_params
 *
 * Capture name is a substring of a pattern from : to /.
 * The rest of the pattern is matched against the request path directly
 * Parameters are captured starting from the next character after
 * the end of the last matched static pattern fragment until the next /.
 *
 * Example pattern:
 * "/path/fragments/:capture/more/fragments/:second_capture"
 * Static fragments:
 * "/path/fragments/", "more/fragments/"
 *
 * Given the following request path:
 * "/path/fragments/:1/more/fragments/:2"
 * the resulting capture will be
 * {{"capture", "1"}, {"second_capture", "2"}}
 */
class PathParamsMatcher final : public MatcherBase {
public:
  PathParamsMatcher(const std::string &pattern);

  bool match(Request &request) const override;

private:
  // Treat segment separators as the end of path parameter capture
  // Does not need to handle query parameters as they are parsed before path
  // matching
  static constexpr char separator = '/';

  // Contains static path fragments to match against, excluding the '/' after
  // path params
  // Fragments are separated by path params
  std::vector<std::string> static_fragments_;
  // Stores the names of the path parameters to be used as keys in the
  // Request::path_params map
  std::vector<std::string> param_names_;
};

/**
 * Performs std::regex_match on request path
 * and stores the result in Request::matches
 *
 * Note that regex match is performed directly on the whole request.
 * This means that wildcard patterns may match multiple path segments with /:
 * "/begin/(.*)/end" will match both "/begin/middle/end" and "/begin/1/2/end".
 */
class RegexMatcher final : public MatcherBase {
public:
  RegexMatcher(const std::string &pattern)
      : MatcherBase(pattern), regex_(pattern) {}

  bool match(Request &request) const override;

private:
  std::regex regex_;
};

ssize_t write_headers(Stream &strm, const Headers &headers);

} // namespace detail

class Server {
public:
  using Handler = std::function<void(const Request &, Response &)>;

  using ExceptionHandler =
      std::function<void(const Request &, Response &, std::exception_ptr ep)>;

  enum class HandlerResponse {
    Handled,
    Unhandled,
  };
  using HandlerWithResponse =
      std::function<HandlerResponse(const Request &, Response &)>;

  using HandlerWithContentReader = std::function<void(
      const Request &, Response &, const ContentReader &content_reader)>;

  using Expect100ContinueHandler =
      std::function<int(const Request &, Response &)>;

  Server();

  virtual ~Server();

  virtual bool is_valid() const;

  Server &Get(const std::string &pattern, Handler handler);
  Server &Post(const std::string &pattern, Handler handler);
  Server &Post(const std::string &pattern, HandlerWithContentReader handler);
  Server &Put(const std::string &pattern, Handler handler);
  Server &Put(const std::string &pattern, HandlerWithContentReader handler);
  Server &Patch(const std::string &pattern, Handler handler);
  Server &Patch(const std::string &pattern, HandlerWithContentReader handler);
  Server &Delete(const std::string &pattern, Handler handler);
  Server &Delete(const std::string &pattern, HandlerWithContentReader handler);
  Server &Options(const std::string &pattern, Handler handler);

  bool set_base_dir(const std::string &dir,
                    const std::string &mount_point = std::string());
  bool set_mount_point(const std::string &mount_point, const std::string &dir,
                       Headers headers = Headers());
  bool remove_mount_point(const std::string &mount_point);
  Server &set_file_extension_and_mimetype_mapping(const std::string &ext,
                                                  const std::string &mime);
  Server &set_default_file_mimetype(const std::string &mime);
  Server &set_file_request_handler(Handler handler);

  template <class ErrorHandlerFunc>
  Server &set_error_handler(ErrorHandlerFunc &&handler) {
    return set_error_handler_core(
        std::forward<ErrorHandlerFunc>(handler),
        std::is_convertible<ErrorHandlerFunc, HandlerWithResponse>{});
  }

  Server &set_exception_handler(ExceptionHandler handler);

  Server &set_pre_routing_handler(HandlerWithResponse handler);
  Server &set_post_routing_handler(Handler handler);

  Server &set_pre_request_handler(HandlerWithResponse handler);

  Server &set_expect_100_continue_handler(Expect100ContinueHandler handler);
  Server &set_logger(Logger logger);
  Server &set_pre_compression_logger(Logger logger);

  Server &set_address_family(int family);
  Server &set_tcp_nodelay(bool on);
  Server &set_ipv6_v6only(bool on);
  Server &set_socket_options(SocketOptions socket_options);

  Server &set_default_headers(Headers headers);
  Server &
  set_header_writer(std::function<ssize_t(Stream &, Headers &)> const &writer);

  Server &set_keep_alive_max_count(size_t count);
  Server &set_keep_alive_timeout(time_t sec);

  Server &set_read_timeout(time_t sec, time_t usec = 0);
  template <class Rep, class Period>
  Server &set_read_timeout(const std::chrono::duration<Rep, Period> &duration);

  Server &set_write_timeout(time_t sec, time_t usec = 0);
  template <class Rep, class Period>
  Server &set_write_timeout(const std::chrono::duration<Rep, Period> &duration);

  Server &set_idle_interval(time_t sec, time_t usec = 0);
  template <class Rep, class Period>
  Server &set_idle_interval(const std::chrono::duration<Rep, Period> &duration);

  Server &set_payload_max_length(size_t length);

  bool bind_to_port(const std::string &host, int port, int socket_flags = 0);
  int bind_to_any_port(const std::string &host, int socket_flags = 0);
  bool listen_after_bind();

  bool listen(const std::string &host, int port, int socket_flags = 0);

  bool is_running() const;
  void wait_until_ready() const;
  void stop();
  void decommission();

  std::function<TaskQueue *(void)> new_task_queue;

protected:
  bool process_request(Stream &strm, const std::string &remote_addr,
                       int remote_port, const std::string &local_addr,
                       int local_port, bool close_connection,
                       bool &connection_closed,
                       const std::function<void(Request &)> &setup_request);

  std::atomic<socket_t> svr_sock_{INVALID_SOCKET};
  size_t keep_alive_max_count_ = CPPHTTPLIB_KEEPALIVE_MAX_COUNT;
  time_t keep_alive_timeout_sec_ = CPPHTTPLIB_KEEPALIVE_TIMEOUT_SECOND;
  time_t read_timeout_sec_ = CPPHTTPLIB_SERVER_READ_TIMEOUT_SECOND;
  time_t read_timeout_usec_ = CPPHTTPLIB_SERVER_READ_TIMEOUT_USECOND;
  time_t write_timeout_sec_ = CPPHTTPLIB_SERVER_WRITE_TIMEOUT_SECOND;
  time_t write_timeout_usec_ = CPPHTTPLIB_SERVER_WRITE_TIMEOUT_USECOND;
  time_t idle_interval_sec_ = CPPHTTPLIB_IDLE_INTERVAL_SECOND;
  time_t idle_interval_usec_ = CPPHTTPLIB_IDLE_INTERVAL_USECOND;
  size_t payload_max_length_ = CPPHTTPLIB_PAYLOAD_MAX_LENGTH;

private:
  using Handlers =
      std::vector<std::pair<std::unique_ptr<detail::MatcherBase>, Handler>>;
  using HandlersForContentReader =
      std::vector<std::pair<std::unique_ptr<detail::MatcherBase>,
                            HandlerWithContentReader>>;

  static std::unique_ptr<detail::MatcherBase>
  make_matcher(const std::string &pattern);

  Server &set_error_handler_core(HandlerWithResponse handler, std::true_type);
  Server &set_error_handler_core(Handler handler, std::false_type);

  socket_t create_server_socket(const std::string &host, int port,
                                int socket_flags,
                                SocketOptions socket_options) const;
  int bind_internal(const std::string &host, int port, int socket_flags);
  bool listen_internal();

  bool routing(Request &req, Response &res, Stream &strm);
  bool handle_file_request(const Request &req, Response &res);
  bool dispatch_request(Request &req, Response &res,
                        const Handlers &handlers) const;
  bool dispatch_request_for_content_reader(
      Request &req, Response &res, ContentReader content_reader,
      const HandlersForContentReader &handlers) const;

  bool parse_request_line(const char *s, Request &req) const;
  void apply_ranges(const Request &req, Response &res,
                    std::string &content_type, std::string &boundary) const;
  bool write_response(Stream &strm, bool close_connection, Request &req,
                      Response &res);
  bool write_response_with_content(Stream &strm, bool close_connection,
                                   const Request &req, Response &res);
  bool write_response_core(Stream &strm, bool close_connection,
                           const Request &req, Response &res,
                           bool need_apply_ranges);
  bool write_content_with_provider(Stream &strm, const Request &req,
                                   Response &res, const std::string &boundary,
                                   const std::string &content_type);
  bool read_content(Stream &strm, Request &req, Response &res);
  bool read_content_with_content_receiver(Stream &strm, Request &req,
                                          Response &res,
                                          ContentReceiver receiver,
                                          FormDataHeader multipart_header,
                                          ContentReceiver multipart_receiver);
  bool read_content_core(Stream &strm, Request &req, Response &res,
                         ContentReceiver receiver,
                         FormDataHeader multipart_header,
                         ContentReceiver multipart_receiver) const;

  virtual bool process_and_close_socket(socket_t sock);

  std::atomic<bool> is_running_{false};
  std::atomic<bool> is_decommissioned{false};

  struct MountPointEntry {
    std::string mount_point;
    std::string base_dir;
    Headers headers;
  };
  std::vector<MountPointEntry> base_dirs_;
  std::map<std::string, std::string> file_extension_and_mimetype_map_;
  std::string default_file_mimetype_ = "application/octet-stream";
  Handler file_request_handler_;

  Handlers get_handlers_;
  Handlers post_handlers_;
  HandlersForContentReader post_handlers_for_content_reader_;
  Handlers put_handlers_;
  HandlersForContentReader put_handlers_for_content_reader_;
  Handlers patch_handlers_;
  HandlersForContentReader patch_handlers_for_content_reader_;
  Handlers delete_handlers_;
  HandlersForContentReader delete_handlers_for_content_reader_;
  Handlers options_handlers_;

  HandlerWithResponse error_handler_;
  ExceptionHandler exception_handler_;
  HandlerWithResponse pre_routing_handler_;
  Handler post_routing_handler_;
  HandlerWithResponse pre_request_handler_;
  Expect100ContinueHandler expect_100_continue_handler_;

  Logger logger_;
  Logger pre_compression_logger_;

  int address_family_ = AF_UNSPEC;
  bool tcp_nodelay_ = CPPHTTPLIB_TCP_NODELAY;
  bool ipv6_v6only_ = CPPHTTPLIB_IPV6_V6ONLY;
  SocketOptions socket_options_ = default_socket_options;

  Headers default_headers_;
  std::function<ssize_t(Stream &, Headers &)> header_writer_ =
      detail::write_headers;
};

enum class Error {
  Success = 0,
  Unknown,
  Connection,
  BindIPAddress,
  Read,
  Write,
  ExceedRedirectCount,
  Canceled,
  SSLConnection,
  SSLLoadingCerts,
  SSLServerVerification,
  SSLServerHostnameVerification,
  UnsupportedMultipartBoundaryChars,
  Compression,
  ConnectionTimeout,
  ProxyConnection,

  // For internal use only
  SSLPeerCouldBeClosed_,
};

std::string to_string(Error error);

std::ostream &operator<<(std::ostream &os, const Error &obj);

class Result {
public:
  Result() = default;
  Result(std::unique_ptr<Response> &&res, Error err,
         Headers &&request_headers = Headers{})
      : res_(std::move(res)), err_(err),
        request_headers_(std::move(request_headers)) {}
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  Result(std::unique_ptr<Response> &&res, Error err, Headers &&request_headers,
         int ssl_error)
      : res_(std::move(res)), err_(err),
        request_headers_(std::move(request_headers)), ssl_error_(ssl_error) {}
  Result(std::unique_ptr<Response> &&res, Error err, Headers &&request_headers,
         int ssl_error, unsigned long ssl_openssl_error)
      : res_(std::move(res)), err_(err),
        request_headers_(std::move(request_headers)), ssl_error_(ssl_error),
        ssl_openssl_error_(ssl_openssl_error) {}
#endif
  // Response
  operator bool() const { return res_ != nullptr; }
  bool operator==(std::nullptr_t) const { return res_ == nullptr; }
  bool operator!=(std::nullptr_t) const { return res_ != nullptr; }
  const Response &value() const { return *res_; }
  Response &value() { return *res_; }
  const Response &operator*() const { return *res_; }
  Response &operator*() { return *res_; }
  const Response *operator->() const { return res_.get(); }
  Response *operator->() { return res_.get(); }

  // Error
  Error error() const { return err_; }

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  // SSL Error
  int ssl_error() const { return ssl_error_; }
  // OpenSSL Error
  unsigned long ssl_openssl_error() const { return ssl_openssl_error_; }
#endif

  // Request Headers
  bool has_request_header(const std::string &key) const;
  std::string get_request_header_value(const std::string &key,
                                       const char *def = "",
                                       size_t id = 0) const;
  size_t get_request_header_value_u64(const std::string &key, size_t def = 0,
                                      size_t id = 0) const;
  size_t get_request_header_value_count(const std::string &key) const;

private:
  std::unique_ptr<Response> res_;
  Error err_ = Error::Unknown;
  Headers request_headers_;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  int ssl_error_ = 0;
  unsigned long ssl_openssl_error_ = 0;
#endif
};

class ClientImpl {
public:
  explicit ClientImpl(const std::string &host);

  explicit ClientImpl(const std::string &host, int port);

  explicit ClientImpl(const std::string &host, int port,
                      const std::string &client_cert_path,
                      const std::string &client_key_path);

  virtual ~ClientImpl();

  virtual bool is_valid() const;

  // clang-format off
  Result Get(const std::string &path, DownloadProgress progress = nullptr);
  Result Get(const std::string &path, ContentReceiver content_receiver, Download
Progress progress = nullptr);
  Result Get(const std::string &path, ResponseHandler response_handler, ContentR
eceiver content_receiver, DownloadProgress progress = nullptr);
  Result Get(const std::string &path, const Headers &headers, DownloadProgress p
rogress = nullptr);
  Result Get(const std::string &path, const Headers &headers, ContentReceiver co
ntent_receiver, DownloadProgress progress = nullptr);
  Result Get(const std::string &path, const Headers &headers, ResponseHandler re
sponse_handler, ContentReceiver content_receiver, DownloadProgress progress = nu
llptr);
  Result Get(const std::string &path, const Params &params, const Headers &heade
rs, DownloadProgress progress = nullptr);
  Result Get(const std::string &path, const Params &params, const Headers &heade
rs, ContentReceiver content_receiver, DownloadProgress progress = nullptr);
  Result Get(const std::string &path, const Params &params, const Headers &heade
rs, ResponseHandler response_handler, ContentReceiver content_receiver, Download
Progress progress = nullptr);

  Result Head(const std::string &path);
  Result Head(const std::string &path, const Headers &headers);

  Result Post(const std::string &path);
  Result Post(const std::string &path, const char *body, size_t content_length,
const std::string &content_type, UploadProgress progress = nullptr);
  Result Post(const std::string &path, const std::string &body, const std::strin
g &content_type, UploadProgress progress = nullptr);
  Result Post(const std::string &path, size_t content_length, ContentProvider co
ntent_provider, const std::string &content_type, UploadProgress progress = nullp
tr);
  Result Post(const std::string &path, ContentProviderWithoutLength content_prov
ider, const std::string &content_type, UploadProgress progress = nullptr);
  Result Post(const std::string &path, const Params &params);
  Result Post(const std::string &path, const UploadFormDataItems &items, UploadP
rogress progress = nullptr);
  Result Post(const std::string &path, const Headers &headers);
  Result Post(const std::string &path, const Headers &headers, const char *body,
 size_t content_length, const std::string &content_type, UploadProgress progress
 = nullptr);
  Result Post(const std::string &path, const Headers &headers, const std::string
 &body, const std::string &content_type, UploadProgress progress = nullptr);
  Result Post(const std::string &path, const Headers &headers, size_t content_le
ngth, ContentProvider content_provider, const std::string &content_type, UploadP
rogress progress = nullptr);
  Result Post(const std::string &path, const Headers &headers, ContentProviderWi
thoutLength content_provider, const std::string &content_type, UploadProgress pr
ogress = nullptr);
  Result Post(const std::string &path, const Headers &headers, const Params &par
ams);
  Result Post(const std::string &path, const Headers &headers, const UploadFormD
ataItems &items, UploadProgress progress = nullptr);
  Result Post(const std::string &path, const Headers &headers, const UploadFormD
ataItems &items, const std::string &boundary, UploadProgress progress = nullptr)
;
  Result Post(const std::string &path, const Headers &headers, const UploadFormD
ataItems &items, const FormDataProviderItems &provider_items, UploadProgress pro
gress = nullptr);
  Result Post(const std::string &path, const Headers &headers, const std::string
 &body, const std::string &content_type, ContentReceiver content_receiver, Downl
oadProgress progress = nullptr);

  Result Put(const std::string &path);
  Result Put(const std::string &path, const char *body, size_t content_length, c
onst std::string &content_type, UploadProgress progress = nullptr);
  Result Put(const std::string &path, const std::string &body, const std::string
 &content_type, UploadProgress progress = nullptr);
  Result Put(const std::string &path, size_t content_length, ContentProvider con
tent_provider, const std::string &content_type, UploadProgress progress = nullpt
r);
  Result Put(const std::string &path, ContentProviderWithoutLength content_provi
der, const std::string &content_type, UploadProgress progress = nullptr);
  Result Put(const std::string &path, const Params &params);
  Result Put(const std::string &path, const UploadFormDataItems &items, UploadPr
ogress progress = nullptr);
  Result Put(const std::string &path, const Headers &headers);
  Result Put(const std::string &path, const Headers &headers, const char *body,
size_t content_length, const std::string &content_type, UploadProgress progress
= nullptr);
  Result Put(const std::string &path, const Headers &headers, const std::string
&body, const std::string &content_type, UploadProgress progress = nullptr);
  Result Put(const std::string &path, const Headers &headers, size_t content_len
gth, ContentProvider content_provider, const std::string &content_type, UploadPr
ogress progress = nullptr);
  Result Put(const std::string &path, const Headers &headers, ContentProviderWit
houtLength content_provider, const std::string &content_type, UploadProgress pro
gress = nullptr);
  Result Put(const std::string &path, const Headers &headers, const Params &para
ms);
  Result Put(const std::string &path, const Headers &headers, const UploadFormDa
taItems &items, UploadProgress progress = nullptr);
  Result Put(const std::string &path, const Headers &headers, const UploadFormDa
taItems &items, const std::string &boundary, UploadProgress progress = nullptr);
  Result Put(const std::string &path, const Headers &headers, const UploadFormDa
taItems &items, const FormDataProviderItems &provider_items, UploadProgress prog
ress = nullptr);
  Result Put(const std::string &path, const Headers &headers, const std::string
&body, const std::string &content_type, ContentReceiver content_receiver, Downlo
adProgress progress = nullptr);

  Result Patch(const std::string &path);
  Result Patch(const std::string &path, const char *body, size_t content_length,
 const std::string &content_type, UploadProgress progress = nullptr);
  Result Patch(const std::string &path, const std::string &body, const std::stri
ng &content_type, UploadProgress progress = nullptr);
  Result Patch(const std::string &path, size_t content_length, ContentProvider c
ontent_provider, const std::string &content_type, UploadProgress progress = null
ptr);
  Result Patch(const std::string &path, ContentProviderWithoutLength content_pro
vider, const std::string &content_type, UploadProgress progress = nullptr);
  Result Patch(const std::string &path, const Params &params);
  Result Patch(const std::string &path, const UploadFormDataItems &items, Upload
Progress progress = nullptr);
  Result Patch(const std::string &path, const Headers &headers, UploadProgress p
rogress = nullptr);
  Result Patch(const std::string &path, const Headers &headers, const char *body
, size_t content_length, const std::string &content_type, UploadProgress progres
s = nullptr);
  Result Patch(const std::string &path, const Headers &headers, const std::strin
g &body, const std::string &content_type, UploadProgress progress = nullptr);
  Result Patch(const std::string &path, const Headers &headers, size_t content_l
ength, ContentProvider content_provider, const std::string &content_type, Upload
Progress progress = nullptr);
  Result Patch(const std::string &path, const Headers &headers, ContentProviderW
ithoutLength content_provider, const std::string &content_type, UploadProgress p
rogress = nullptr);
  Result Patch(const std::string &path, const Headers &headers, const Params &pa
rams);
  Result Patch(const std::string &path, const Headers &headers, const UploadForm
DataItems &items, UploadProgress progress = nullptr);
  Result Patch(const std::string &path, const Headers &headers, const UploadForm
DataItems &items, const std::string &boundary, UploadProgress progress = nullptr
);
  Result Patch(const std::string &path, const Headers &headers, const UploadForm
DataItems &items, const FormDataProviderItems &provider_items, UploadProgress pr
ogress = nullptr);
  Result Patch(const std::string &path, const Headers &headers, const std::strin
g &body, const std::string &content_type, ContentReceiver content_receiver, Down
loadProgress progress = nullptr);

  Result Delete(const std::string &path, DownloadProgress progress = nullptr);
  Result Delete(const std::string &path, const char *body, size_t content_length
, const std::string &content_type, DownloadProgress progress = nullptr);
  Result Delete(const std::string &path, const std::string &body, const std::str
ing &content_type, DownloadProgress progress = nullptr);
  Result Delete(const std::string &path, const Params &params, DownloadProgress
progress = nullptr);
  Result Delete(const std::string &path, const Headers &headers, DownloadProgres
s progress = nullptr);
  Result Delete(const std::string &path, const Headers &headers, const char *bod
y, size_t content_length, const std::string &content_type, DownloadProgress prog
ress = nullptr);
  Result Delete(const std::string &path, const Headers &headers, const std::stri
ng &body, const std::string &content_type, DownloadProgress progress = nullptr);
  Result Delete(const std::string &path, const Headers &headers, const Params &p
arams, DownloadProgress progress = nullptr);

  Result Options(const std::string &path);
  Result Options(const std::string &path, const Headers &headers);
  // clang-format on

  bool send(Request &req, Response &res, Error &error);
  Result send(const Request &req);

  void stop();

  std::string host() const;
  int port() const;

  size_t is_socket_open() const;
  socket_t socket() const;

  void set_hostname_addr_map(std::map<std::string, std::string> addr_map);

  void set_default_headers(Headers headers);

  void
  set_header_writer(std::function<ssize_t(Stream &, Headers &)> const &writer);

  void set_address_family(int family);
  void set_tcp_nodelay(bool on);
  void set_ipv6_v6only(bool on);
  void set_socket_options(SocketOptions socket_options);

  void set_connection_timeout(time_t sec, time_t usec = 0);
  template <class Rep, class Period>
  void
  set_connection_timeout(const std::chrono::duration<Rep, Period> &duration);

  void set_read_timeout(time_t sec, time_t usec = 0);
  template <class Rep, class Period>
  void set_read_timeout(const std::chrono::duration<Rep, Period> &duration);

  void set_write_timeout(time_t sec, time_t usec = 0);
  template <class Rep, class Period>
  void set_write_timeout(const std::chrono::duration<Rep, Period> &duration);

  void set_max_timeout(time_t msec);
  template <class Rep, class Period>
  void set_max_timeout(const std::chrono::duration<Rep, Period> &duration);

  void set_basic_auth(const std::string &username, const std::string &password);
  void set_bearer_token_auth(const std::string &token);
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  void set_digest_auth(const std::string &username,
                       const std::string &password);
#endif

  void set_keep_alive(bool on);
  void set_follow_location(bool on);

  void set_path_encode(bool on);

  void set_compress(bool on);

  void set_decompress(bool on);

  void set_interface(const std::string &intf);

  void set_proxy(const std::string &host, int port);
  void set_proxy_basic_auth(const std::string &username,
                            const std::string &password);
  void set_proxy_bearer_token_auth(const std::string &token);
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  void set_proxy_digest_auth(const std::string &username,
                             const std::string &password);
#endif

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  void set_ca_cert_path(const std::string &ca_cert_file_path,
                        const std::string &ca_cert_dir_path = std::string());
  void set_ca_cert_store(X509_STORE *ca_cert_store);
  X509_STORE *create_ca_cert_store(const char *ca_cert, std::size_t size) const;
#endif

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  void enable_server_certificate_verification(bool enabled);
  void enable_server_hostname_verification(bool enabled);
  void set_server_certificate_verifier(
      std::function<SSLVerifierResponse(SSL *ssl)> verifier);
#endif

  void set_logger(Logger logger);

protected:
  struct Socket {
    socket_t sock = INVALID_SOCKET;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    SSL *ssl = nullptr;
#endif

    bool is_open() const { return sock != INVALID_SOCKET; }
  };

  virtual bool create_and_connect_socket(Socket &socket, Error &error);

  // All of:
  //   shutdown_ssl
  //   shutdown_socket
  //   close_socket
  // should ONLY be called when socket_mutex_ is locked.
  // Also, shutdown_ssl and close_socket should also NOT be called concurrently
  // with a DIFFERENT thread sending requests using that socket.
  virtual void shutdown_ssl(Socket &socket, bool shutdown_gracefully);
  void shutdown_socket(Socket &socket) const;
  void close_socket(Socket &socket);

  bool process_request(Stream &strm, Request &req, Response &res,
                       bool close_connection, Error &error);

  bool write_content_with_provider(Stream &strm, const Request &req,
                                   Error &error) const;

  void copy_settings(const ClientImpl &rhs);

  // Socket endpoint information
  const std::string host_;
  const int port_;
  const std::string host_and_port_;

  // Current open socket
  Socket socket_;
  mutable std::mutex socket_mutex_;
  std::recursive_mutex request_mutex_;

  // These are all protected under socket_mutex
  size_t socket_requests_in_flight_ = 0;
  std::thread::id socket_requests_are_from_thread_ = std::thread::id();
  bool socket_should_be_closed_when_request_is_done_ = false;

  // Hostname-IP map
  std::map<std::string, std::string> addr_map_;

  // Default headers
  Headers default_headers_;

  // Header writer
  std::function<ssize_t(Stream &, Headers &)> header_writer_ =
      detail::write_headers;

  // Settings
  std::string client_cert_path_;
  std::string client_key_path_;

  time_t connection_timeout_sec_ = CPPHTTPLIB_CONNECTION_TIMEOUT_SECOND;
  time_t connection_timeout_usec_ = CPPHTTPLIB_CONNECTION_TIMEOUT_USECOND;
  time_t read_timeout_sec_ = CPPHTTPLIB_CLIENT_READ_TIMEOUT_SECOND;
  time_t read_timeout_usec_ = CPPHTTPLIB_CLIENT_READ_TIMEOUT_USECOND;
  time_t write_timeout_sec_ = CPPHTTPLIB_CLIENT_WRITE_TIMEOUT_SECOND;
  time_t write_timeout_usec_ = CPPHTTPLIB_CLIENT_WRITE_TIMEOUT_USECOND;
  time_t max_timeout_msec_ = CPPHTTPLIB_CLIENT_MAX_TIMEOUT_MSECOND;

  std::string basic_auth_username_;
  std::string basic_auth_password_;
  std::string bearer_token_auth_token_;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  std::string digest_auth_username_;
  std::string digest_auth_password_;
#endif

  bool keep_alive_ = false;
  bool follow_location_ = false;

  bool path_encode_ = true;

  int address_family_ = AF_UNSPEC;
  bool tcp_nodelay_ = CPPHTTPLIB_TCP_NODELAY;
  bool ipv6_v6only_ = CPPHTTPLIB_IPV6_V6ONLY;
  SocketOptions socket_options_ = nullptr;

  bool compress_ = false;
  bool decompress_ = true;

  std::string interface_;

  std::string proxy_host_;
  int proxy_port_ = -1;

  std::string proxy_basic_auth_username_;
  std::string proxy_basic_auth_password_;
  std::string proxy_bearer_token_auth_token_;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  std::string proxy_digest_auth_username_;
  std::string proxy_digest_auth_password_;
#endif

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  std::string ca_cert_file_path_;
  std::string ca_cert_dir_path_;

  X509_STORE *ca_cert_store_ = nullptr;
#endif

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  bool server_certificate_verification_ = true;
  bool server_hostname_verification_ = true;
  std::function<SSLVerifierResponse(SSL *ssl)> server_certificate_verifier_;
#endif

  Logger logger_;

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  int last_ssl_error_ = 0;
  unsigned long last_openssl_error_ = 0;
#endif

private:
  bool send_(Request &req, Response &res, Error &error);
  Result send_(Request &&req);

  socket_t create_client_socket(Error &error) const;
  bool read_response_line(Stream &strm, const Request &req,
                          Response &res) const;
  bool write_request(Stream &strm, Request &req, bool close_connection,
                     Error &error);
  bool redirect(Request &req, Response &res, Error &error);
  bool create_redirect_client(const std::string &scheme,
                              const std::string &host, int port, Request &req,
                              Response &res, const std::string &path,
                              const std::string &location, Error &error);
  template <typename ClientType> void setup_redirect_client(ClientType &client);
  bool handle_request(Stream &strm, Request &req, Response &res,
                      bool close_connection, Error &error);
  std::unique_ptr<Response> send_with_content_provider(
      Request &req, const char *body, size_t content_length,
      ContentProvider content_provider,
      ContentProviderWithoutLength content_provider_without_length,
      const std::string &content_type, Error &error);
  Result send_with_content_provider(
      const std::string &method, const std::string &path,
      const Headers &headers, const char *body, size_t content_length,
      ContentProvider content_provider,
      ContentProviderWithoutLength content_provider_without_length,
      const std::string &content_type, UploadProgress progress);
  ContentProviderWithoutLength get_multipart_content_provider(
      const std::string &boundary, const UploadFormDataItems &items,
      const FormDataProviderItems &provider_items) const;

  std::string adjust_host_string(const std::string &host) const;

  virtual bool
  process_socket(const Socket &socket,
                 std::chrono::time_point<std::chrono::steady_clock> start_time,
                 std::function<bool(Stream &strm)> callback);
  virtual bool is_ssl() const;
};

class Client {
public:
  // Universal interface
  explicit Client(const std::string &scheme_host_port);

  explicit Client(const std::string &scheme_host_port,
                  const std::string &client_cert_path,
                  const std::string &client_key_path);

  // HTTP only interface
  explicit Client(const std::string &host, int port);

  explicit Client(const std::string &host, int port,
                  const std::string &client_cert_path,
                  const std::string &client_key_path);

  Client(Client &&) = default;
  Client &operator=(Client &&) = default;

  ~Client();

  bool is_valid() const;

  // clang-format off
  Result Get(const std::string &path, DownloadProgress progress = nullptr);
  Result Get(const std::string &path, ContentReceiver content_receiver, Download
Progress progress = nullptr);
  Result Get(const std::string &path, ResponseHandler response_handler, ContentR
eceiver content_receiver, DownloadProgress progress = nullptr);
  Result Get(const std::string &path, const Headers &headers, DownloadProgress p
rogress = nullptr);
  Result Get(const std::string &path, const Headers &headers, ContentReceiver co
ntent_receiver, DownloadProgress progress = nullptr);
  Result Get(const std::string &path, const Headers &headers, ResponseHandler re
sponse_handler, ContentReceiver content_receiver, DownloadProgress progress = nu
llptr);
  Result Get(const std::string &path, const Params &params, const Headers &heade
rs, DownloadProgress progress = nullptr);
  Result Get(const std::string &path, const Params &params, const Headers &heade
rs, ContentReceiver content_receiver, DownloadProgress progress = nullptr);
  Result Get(const std::string &path, const Params &params, const Headers &heade
rs, ResponseHandler response_handler, ContentReceiver content_receiver, Download
Progress progress = nullptr);

  Result Head(const std::string &path);
  Result Head(const std::string &path, const Headers &headers);

  Result Post(const std::string &path);
  Result Post(const std::string &path, const char *body, size_t content_length,
const std::string &content_type, UploadProgress progress = nullptr);
  Result Post(const std::string &path, const std::string &body, const std::strin
g &content_type, UploadProgress progress = nullptr);
  Result Post(const std::string &path, size_t content_length, ContentProvider co
ntent_provider, const std::string &content_type, UploadProgress progress = nullp
tr);
  Result Post(const std::string &path, ContentProviderWithoutLength content_prov
ider, const std::string &content_type, UploadProgress progress = nullptr);
  Result Post(const std::string &path, const Params &params);
  Result Post(const std::string &path, const UploadFormDataItems &items, UploadP
rogress progress = nullptr);
  Result Post(const std::string &path, const Headers &headers);
  Result Post(const std::string &path, const Headers &headers, const char *body,
 size_t content_length, const std::string &content_type, UploadProgress progress
 = nullptr);
  Result Post(const std::string &path, const Headers &headers, const std::string
 &body, const std::string &content_type, UploadProgress progress = nullptr);
  Result Post(const std::string &path, const Headers &headers, size_t content_le
ngth, ContentProvider content_provider, const std::string &content_type, UploadP
rogress progress = nullptr);
  Result Post(const std::string &path, const Headers &headers, ContentProviderWi
thoutLength content_provider, const std::string &content_type, UploadProgress pr
ogress = nullptr);
  Result Post(const std::string &path, const Headers &headers, const Params &par
ams);
  Result Post(const std::string &path, const Headers &headers, const UploadFormD
ataItems &items, UploadProgress progress = nullptr);
  Result Post(const std::string &path, const Headers &headers, const UploadFormD
ataItems &items, const std::string &boundary, UploadProgress progress = nullptr)
;
  Result Post(const std::string &path, const Headers &headers, const UploadFormD
ataItems &items, const FormDataProviderItems &provider_items, UploadProgress pro
gress = nullptr);
  Result Post(const std::string &path, const Headers &headers, const std::string
 &body, const std::string &content_type, ContentReceiver content_receiver, Downl
oadProgress progress = nullptr);

  Result Put(const std::string &path);
  Result Put(const std::string &path, const char *body, size_t content_length, c
onst std::string &content_type, UploadProgress progress = nullptr);
  Result Put(const std::string &path, const std::string &body, const std::string
 &content_type, UploadProgress progress = nullptr);
  Result Put(const std::string &path, size_t content_length, ContentProvider con
tent_provider, const std::string &content_type, UploadProgress progress = nullpt
r);
  Result Put(const std::string &path, ContentProviderWithoutLength content_provi
der, const std::string &content_type, UploadProgress progress = nullptr);
  Result Put(const std::string &path, const Params &params);
  Result Put(const std::string &path, const UploadFormDataItems &items, UploadPr
ogress progress = nullptr);
  Result Put(const std::string &path, const Headers &headers);
  Result Put(const std::string &path, const Headers &headers, const char *body,
size_t content_length, const std::string &content_type, UploadProgress progress
= nullptr);
  Result Put(const std::string &path, const Headers &headers, const std::string
&body, const std::string &content_type, UploadProgress progress = nullptr);
  Result Put(const std::string &path, const Headers &headers, size_t content_len
gth, ContentProvider content_provider, const std::string &content_type, UploadPr
ogress progress = nullptr);
  Result Put(const std::string &path, const Headers &headers, ContentProviderWit
houtLength content_provider, const std::string &content_type, UploadProgress pro
gress = nullptr);
  Result Put(const std::string &path, const Headers &headers, const Params &para
ms);
  Result Put(const std::string &path, const Headers &headers, const UploadFormDa
taItems &items, UploadProgress progress = nullptr);
  Result Put(const std::string &path, const Headers &headers, const UploadFormDa
taItems &items, const std::string &boundary, UploadProgress progress = nullptr);
  Result Put(const std::string &path, const Headers &headers, const UploadFormDa
taItems &items, const FormDataProviderItems &provider_items, UploadProgress prog
ress = nullptr);
  Result Put(const std::string &path, const Headers &headers, const std::string
&body, const std::string &content_type, ContentReceiver content_receiver, Downlo
adProgress progress = nullptr);

  Result Patch(const std::string &path);
  Result Patch(const std::string &path, const char *body, size_t content_length,
 const std::string &content_type, UploadProgress progress = nullptr);
  Result Patch(const std::string &path, const std::string &body, const std::stri
ng &content_type, UploadProgress progress = nullptr);
  Result Patch(const std::string &path, size_t content_length, ContentProvider c
ontent_provider, const std::string &content_type, UploadProgress progress = null
ptr);
  Result Patch(const std::string &path, ContentProviderWithoutLength content_pro
vider, const std::string &content_type, UploadProgress progress = nullptr);
  Result Patch(const std::string &path, const Params &params);
  Result Patch(const std::string &path, const UploadFormDataItems &items, Upload
Progress progress = nullptr);
  Result Patch(const std::string &path, const Headers &headers);
  Result Patch(const std::string &path, const Headers &headers, const char *body
, size_t content_length, const std::string &content_type, UploadProgress progres
s = nullptr);
  Result Patch(const std::string &path, const Headers &headers, const std::strin
g &body, const std::string &content_type, UploadProgress progress = nullptr);
  Result Patch(const std::string &path, const Headers &headers, size_t content_l
ength, ContentProvider content_provider, const std::string &content_type, Upload
Progress progress = nullptr);
  Result Patch(const std::string &path, const Headers &headers, ContentProviderW
ithoutLength content_provider, const std::string &content_type, UploadProgress p
rogress = nullptr);
  Result Patch(const std::string &path, const Headers &headers, const Params &pa
rams);
  Result Patch(const std::string &path, const Headers &headers, const UploadForm
DataItems &items, UploadProgress progress = nullptr);
  Result Patch(const std::string &path, const Headers &headers, const UploadForm
DataItems &items, const std::string &boundary, UploadProgress progress = nullptr
);
  Result Patch(const std::string &path, const Headers &headers, const UploadForm
DataItems &items, const FormDataProviderItems &provider_items, UploadProgress pr
ogress = nullptr);
  Result Patch(const std::string &path, const Headers &headers, const std::strin
g &body, const std::string &content_type, ContentReceiver content_receiver, Down
loadProgress progress = nullptr);

  Result Delete(const std::string &path, DownloadProgress progress = nullptr);
  Result Delete(const std::string &path, const char *body, size_t content_length
, const std::string &content_type, DownloadProgress progress = nullptr);
  Result Delete(const std::string &path, const std::string &body, const std::str
ing &content_type, DownloadProgress progress = nullptr);
  Result Delete(const std::string &path, const Params &params, DownloadProgress
progress = nullptr);
  Result Delete(const std::string &path, const Headers &headers, DownloadProgres
s progress = nullptr);
  Result Delete(const std::string &path, const Headers &headers, const char *bod
y, size_t content_length, const std::string &content_type, DownloadProgress prog
ress = nullptr);
  Result Delete(const std::string &path, const Headers &headers, const std::stri
ng &body, const std::string &content_type, DownloadProgress progress = nullptr);
  Result Delete(const std::string &path, const Headers &headers, const Params &p
arams, DownloadProgress progress = nullptr);

  Result Options(const std::string &path);
  Result Options(const std::string &path, const Headers &headers);
  // clang-format on

  bool send(Request &req, Response &res, Error &error);
  Result send(const Request &req);

  void stop();

  std::string host() const;
  int port() const;

  size_t is_socket_open() const;
  socket_t socket() const;

  void set_hostname_addr_map(std::map<std::string, std::string> addr_map);

  void set_default_headers(Headers headers);

  void
  set_header_writer(std::function<ssize_t(Stream &, Headers &)> const &writer);

  void set_address_family(int family);
  void set_tcp_nodelay(bool on);
  void set_socket_options(SocketOptions socket_options);

  void set_connection_timeout(time_t sec, time_t usec = 0);
  template <class Rep, class Period>
  void
  set_connection_timeout(const std::chrono::duration<Rep, Period> &duration);

  void set_read_timeout(time_t sec, time_t usec = 0);
  template <class Rep, class Period>
  void set_read_timeout(const std::chrono::duration<Rep, Period> &duration);

  void set_write_timeout(time_t sec, time_t usec = 0);
  template <class Rep, class Period>
  void set_write_timeout(const std::chrono::duration<Rep, Period> &duration);

  void set_max_timeout(time_t msec);
  template <class Rep, class Period>
  void set_max_timeout(const std::chrono::duration<Rep, Period> &duration);

  void set_basic_auth(const std::string &username, const std::string &password);
  void set_bearer_token_auth(const std::string &token);
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  void set_digest_auth(const std::string &username,
                       const std::string &password);
#endif

  void set_keep_alive(bool on);
  void set_follow_location(bool on);

  void set_path_encode(bool on);
  void set_url_encode(bool on);

  void set_compress(bool on);

  void set_decompress(bool on);

  void set_interface(const std::string &intf);

  void set_proxy(const std::string &host, int port);
  void set_proxy_basic_auth(const std::string &username,
                            const std::string &password);
  void set_proxy_bearer_token_auth(const std::string &token);
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  void set_proxy_digest_auth(const std::string &username,
                             const std::string &password);
#endif

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  void enable_server_certificate_verification(bool enabled);
  void enable_server_hostname_verification(bool enabled);
  void set_server_certificate_verifier(
      std::function<SSLVerifierResponse(SSL *ssl)> verifier);
#endif

  void set_logger(Logger logger);

  // SSL
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  void set_ca_cert_path(const std::string &ca_cert_file_path,
                        const std::string &ca_cert_dir_path = std::string());

  void set_ca_cert_store(X509_STORE *ca_cert_store);
  void load_ca_cert_store(const char *ca_cert, std::size_t size);

  long get_openssl_verify_result() const;

  SSL_CTX *ssl_context() const;
#endif

private:
  std::unique_ptr<ClientImpl> cli_;

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  bool is_ssl_ = false;
#endif
};

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
class SSLServer : public Server {
public:
  SSLServer(const char *cert_path, const char *private_key_path,
            const char *client_ca_cert_file_path = nullptr,
            const char *client_ca_cert_dir_path = nullptr,
            const char *private_key_password = nullptr);

  SSLServer(X509 *cert, EVP_PKEY *private_key,
            X509_STORE *client_ca_cert_store = nullptr);

  SSLServer(
      const std::function<bool(SSL_CTX &ssl_ctx)> &setup_ssl_ctx_callback);

  ~SSLServer() override;

  bool is_valid() const override;

  SSL_CTX *ssl_context() const;

  void update_certs(X509 *cert, EVP_PKEY *private_key,
                    X509_STORE *client_ca_cert_store = nullptr);

private:
  bool process_and_close_socket(socket_t sock) override;

  SSL_CTX *ctx_;
  std::mutex ctx_mutex_;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  int last_ssl_error_ = 0;
#endif
};

class SSLClient final : public ClientImpl {
public:
  explicit SSLClient(const std::string &host);

  explicit SSLClient(const std::string &host, int port);

  explicit SSLClient(const std::string &host, int port,
                     const std::string &client_cert_path,
                     const std::string &client_key_path,
                     const std::string &private_key_password = std::string());

  explicit SSLClient(const std::string &host, int port, X509 *client_cert,
                     EVP_PKEY *client_key,
                     const std::string &private_key_password = std::string());

  ~SSLClient() override;

  bool is_valid() const override;

  void set_ca_cert_store(X509_STORE *ca_cert_store);
  void load_ca_cert_store(const char *ca_cert, std::size_t size);

  long get_openssl_verify_result() const;

  SSL_CTX *ssl_context() const;

private:
  bool create_and_connect_socket(Socket &socket, Error &error) override;
  void shutdown_ssl(Socket &socket, bool shutdown_gracefully) override;
  void shutdown_ssl_impl(Socket &socket, bool shutdown_gracefully);

  bool
  process_socket(const Socket &socket,
                 std::chrono::time_point<std::chrono::steady_clock> start_time,
                 std::function<bool(Stream &strm)> callback) override;
  bool is_ssl() const override;

  bool connect_with_proxy(
      Socket &sock,
      std::chrono::time_point<std::chrono::steady_clock> start_time,
      Response &res, bool &success, Error &error);
  bool initialize_ssl(Socket &socket, Error &error);

  bool load_certs();

  bool verify_host(X509 *server_cert) const;
  bool verify_host_with_subject_alt_name(X509 *server_cert) const;
  bool verify_host_with_common_name(X509 *server_cert) const;
  bool check_host_name(const char *pattern, size_t pattern_len) const;

  SSL_CTX *ctx_;
  std::mutex ctx_mutex_;
  std::once_flag initialize_cert_;

  std::vector<std::string> host_components_;

  long verify_result_ = 0;

  friend class ClientImpl;
};
#endif

/*
 * Implementation of template methods.
 */

namespace detail {

template <typename T, typename U>
inline void duration_to_sec_and_usec(const T &duration, U callback) {
  auto sec = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
  auto usec = std::chrono::duration_cast<std::chrono::microseconds>(
                  duration - std::chrono::seconds(sec))
                  .count();
  callback(static_cast<time_t>(sec), static_cast<time_t>(usec));
}

template <size_t N> inline constexpr size_t str_len(const char (&)[N]) {
  return N - 1;
}

inline bool is_numeric(const std::string &str) {
  return !str.empty() &&
         std::all_of(str.cbegin(), str.cend(),
                     [](unsigned char c) { return std::isdigit(c); });
}

inline size_t get_header_value_u64(const Headers &headers,
                                   const std::string &key, size_t def,
                                   size_t id, bool &is_invalid_value) {
  is_invalid_value = false;
  auto rng = headers.equal_range(key);
  auto it = rng.first;
  std::advance(it, static_cast<ssize_t>(id));
  if (it != rng.second) {
    if (is_numeric(it->second)) {
      return std::strtoull(it->second.data(), nullptr, 10);
    } else {
      is_invalid_value = true;
    }
  }
  return def;
}

inline size_t get_header_value_u64(const Headers &headers,
                                   const std::string &key, size_t def,
                                   size_t id) {
  bool dummy = false;
  return get_header_value_u64(headers, key, def, id, dummy);
}

} // namespace detail

inline size_t Request::get_header_value_u64(const std::string &key, size_t def,
                                            size_t id) const {
  return detail::get_header_value_u64(headers, key, def, id);
}

inline size_t Response::get_header_value_u64(const std::string &key, size_t def,
                                             size_t id) const {
  return detail::get_header_value_u64(headers, key, def, id);
}

namespace detail {

inline bool set_socket_opt_impl(socket_t sock, int level, int optname,
                                const void *optval, socklen_t optlen) {
  return setsockopt(sock, level, optname,
#ifdef _WIN64
                    reinterpret_cast<const char *>(optval),
#else
                    optval,
#endif
                    optlen) == 0;
}

inline bool set_socket_opt(socket_t sock, int level, int optname, int optval) {
  return set_socket_opt_impl(sock, level, optname, &optval, sizeof(optval));
}

inline bool set_socket_opt_time(socket_t sock, int level, int optname,
                                time_t sec, time_t usec) {
#ifdef _WIN64
  auto timeout = static_cast<uint32_t>(sec * 1000 + usec / 1000);
#else
  timeval timeout;
  timeout.tv_sec = static_cast<long>(sec);
  timeout.tv_usec = static_cast<decltype(timeout.tv_usec)>(usec);
#endif
  return set_socket_opt_impl(sock, level, optname, &timeout, sizeof(timeout));
}

} // namespace detail

inline void default_socket_options(socket_t sock) {
  detail::set_socket_opt(sock, SOL_SOCKET,
#ifdef SO_REUSEPORT
                         SO_REUSEPORT,
#else
                         SO_REUSEADDR,
#endif
                         1);
}

inline const char *status_message(int status) {
  switch (status) {
  case StatusCode::Continue_100: return "Continue";
  case StatusCode::SwitchingProtocol_101: return "Switching Protocol";
  case StatusCode::Processing_102: return "Processing";
  case StatusCode::EarlyHints_103: return "Early Hints";
  case StatusCode::OK_200: return "OK";
  case StatusCode::Created_201: return "Created";
  case StatusCode::Accepted_202: return "Accepted";
  case StatusCode::NonAuthoritativeInformation_203:
    return "Non-Authoritative Information";
  case StatusCode::NoContent_204: return "No Content";
  case StatusCode::ResetContent_205: return "Reset Content";
  case StatusCode::PartialContent_206: return "Partial Content";
  case StatusCode::MultiStatus_207: return "Multi-Status";
  case StatusCode::AlreadyReported_208: return "Already Reported";
  case StatusCode::IMUsed_226: return "IM Used";
  case StatusCode::MultipleChoices_300: return "Multiple Choices";
  case StatusCode::MovedPermanently_301: return "Moved Permanently";
  case StatusCode::Found_302: return "Found";
  case StatusCode::SeeOther_303: return "See Other";
  case StatusCode::NotModified_304: return "Not Modified";
  case StatusCode::UseProxy_305: return "Use Proxy";
  case StatusCode::unused_306: return "unused";
  case StatusCode::TemporaryRedirect_307: return "Temporary Redirect";
  case StatusCode::PermanentRedirect_308: return "Permanent Redirect";
  case StatusCode::BadRequest_400: return "Bad Request";
  case StatusCode::Unauthorized_401: return "Unauthorized";
  case StatusCode::PaymentRequired_402: return "Payment Required";
  case StatusCode::Forbidden_403: return "Forbidden";
  case StatusCode::NotFound_404: return "Not Found";
  case StatusCode::MethodNotAllowed_405: return "Method Not Allowed";
  case StatusCode::NotAcceptable_406: return "Not Acceptable";
  case StatusCode::ProxyAuthenticationRequired_407:
    return "Proxy Authentication Required";
  case StatusCode::RequestTimeout_408: return "Request Timeout";
  case StatusCode::Conflict_409: return "Conflict";
  case StatusCode::Gone_410: return "Gone";
  case StatusCode::LengthRequired_411: return "Length Required";
  case StatusCode::PreconditionFailed_412: return "Precondition Failed";
  case StatusCode::PayloadTooLarge_413: return "Payload Too Large";
  case StatusCode::UriTooLong_414: return "URI Too Long";
  case StatusCode::UnsupportedMediaType_415: return "Unsupported Media Type";
  case StatusCode::RangeNotSatisfiable_416: return "Range Not Satisfiable";
  case StatusCode::ExpectationFailed_417: return "Expectation Failed";
  case StatusCode::ImATeapot_418: return "I'm a teapot";
  case StatusCode::MisdirectedRequest_421: return "Misdirected Request";
  case StatusCode::UnprocessableContent_422: return "Unprocessable Content";
  case StatusCode::Locked_423: return "Locked";
  case StatusCode::FailedDependency_424: return "Failed Dependency";
  case StatusCode::TooEarly_425: return "Too Early";
  case StatusCode::UpgradeRequired_426: return "Upgrade Required";
  case StatusCode::PreconditionRequired_428: return "Precondition Required";
  case StatusCode::TooManyRequests_429: return "Too Many Requests";
  case StatusCode::RequestHeaderFieldsTooLarge_431:
    return "Request Header Fields Too Large";
  case StatusCode::UnavailableForLegalReasons_451:
    return "Unavailable For Legal Reasons";
  case StatusCode::NotImplemented_501: return "Not Implemented";
  case StatusCode::BadGateway_502: return "Bad Gateway";
  case StatusCode::ServiceUnavailable_503: return "Service Unavailable";
  case StatusCode::GatewayTimeout_504: return "Gateway Timeout";
  case StatusCode::HttpVersionNotSupported_505:
    return "HTTP Version Not Supported";
  case StatusCode::VariantAlsoNegotiates_506: return "Variant Also Negotiates";
  case StatusCode::InsufficientStorage_507: return "Insufficient Storage";
  case StatusCode::LoopDetected_508: return "Loop Detected";
  case StatusCode::NotExtended_510: return "Not Extended";
  case StatusCode::NetworkAuthenticationRequired_511:
    return "Network Authentication Required";

  default:
  case StatusCode::InternalServerError_500: return "Internal Server Error";
  }
}

inline std::string get_bearer_token_auth(const Request &req) {
  if (req.has_header("Authorization")) {
    constexpr auto bearer_header_prefix_len = detail::str_len("Bearer ");
    return req.get_header_value("Authorization")
        .substr(bearer_header_prefix_len);
  }
  return "";
}

template <class Rep, class Period>
inline Server &
Server::set_read_timeout(const std::chrono::duration<Rep, Period> &duration) {
  detail::duration_to_sec_and_usec(
      duration, [&](time_t sec, time_t usec) { set_read_timeout(sec, usec); });
  return *this;
}

template <class Rep, class Period>
inline Server &
Server::set_write_timeout(const std::chrono::duration<Rep, Period> &duration) {
  detail::duration_to_sec_and_usec(
      duration, [&](time_t sec, time_t usec) { set_write_timeout(sec, usec); });
  return *this;
}

template <class Rep, class Period>
inline Server &
Server::set_idle_interval(const std::chrono::duration<Rep, Period> &duration) {
  detail::duration_to_sec_and_usec(
      duration, [&](time_t sec, time_t usec) { set_idle_interval(sec, usec); });
  return *this;
}

inline std::string to_string(const Error error) {
  switch (error) {
  case Error::Success: return "Success (no error)";
  case Error::Connection: return "Could not establish connection";
  case Error::BindIPAddress: return "Failed to bind IP address";
  case Error::Read: return "Failed to read connection";
  case Error::Write: return "Failed to write connection";
  case Error::ExceedRedirectCount: return "Maximum redirect count exceeded";
  case Error::Canceled: return "Connection handling canceled";
  case Error::SSLConnection: return "SSL connection failed";
  case Error::SSLLoadingCerts: return "SSL certificate loading failed";
  case Error::SSLServerVerification: return "SSL server verification failed";
  case Error::SSLServerHostnameVerification:
    return "SSL server hostname verification failed";
  case Error::UnsupportedMultipartBoundaryChars:
    return "Unsupported HTTP multipart boundary characters";
  case Error::Compression: return "Compression failed";
  case Error::ConnectionTimeout: return "Connection timed out";
  case Error::ProxyConnection: return "Proxy connection failed";
  case Error::Unknown: return "Unknown";
  default: break;
  }

  return "Invalid";
}

inline std::ostream &operator<<(std::ostream &os, const Error &obj) {
  os << to_string(obj);
  os << " (" << static_cast<std::underlying_type<Error>::type>(obj) << ')';
  return os;
}

inline size_t Result::get_request_header_value_u64(const std::string &key,
                                                   size_t def,
                                                   size_t id) const {
  return detail::get_header_value_u64(request_headers_, key, def, id);
}

template <class Rep, class Period>
inline void ClientImpl::set_connection_timeout(
    const std::chrono::duration<Rep, Period> &duration) {
  detail::duration_to_sec_and_usec(duration, [&](time_t sec, time_t usec) {
    set_connection_timeout(sec, usec);
  });
}

template <class Rep, class Period>
inline void ClientImpl::set_read_timeout(
    const std::chrono::duration<Rep, Period> &duration) {
  detail::duration_to_sec_and_usec(
      duration, [&](time_t sec, time_t usec) { set_read_timeout(sec, usec); });
}

template <class Rep, class Period>
inline void ClientImpl::set_write_timeout(
    const std::chrono::duration<Rep, Period> &duration) {
  detail::duration_to_sec_and_usec(
      duration, [&](time_t sec, time_t usec) { set_write_timeout(sec, usec); });
}

template <class Rep, class Period>
inline void ClientImpl::set_max_timeout(
    const std::chrono::duration<Rep, Period> &duration) {
  auto msec =
      std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
  set_max_timeout(msec);
}

template <class Rep, class Period>
inline void Client::set_connection_timeout(
    const std::chrono::duration<Rep, Period> &duration) {
  cli_->set_connection_timeout(duration);
}

template <class Rep, class Period>
inline void
Client::set_read_timeout(const std::chrono::duration<Rep, Period> &duration) {
  cli_->set_read_timeout(duration);
}

template <class Rep, class Period>
inline void
Client::set_write_timeout(const std::chrono::duration<Rep, Period> &duration) {
  cli_->set_write_timeout(duration);
}

template <class Rep, class Period>
inline void
Client::set_max_timeout(const std::chrono::duration<Rep, Period> &duration) {
  cli_->set_max_timeout(duration);
}

/*
 * Forward declarations and types that will be part of the .h file if split into
 * .h + .cc.
 */

std::string hosted_at(const std::string &hostname);

void hosted_at(const std::string &hostname, std::vector<std::string> &addrs);

std::string encode_uri_component(const std::string &value);

std::string encode_uri(const std::string &value);

std::string decode_uri_component(const std::string &value);

std::string decode_uri(const std::string &value);

std::string encode_query_param(const std::string &value);

std::string append_query_params(const std::string &path, const Params &params);

std::pair<std::string, std::string> make_range_header(const Ranges &ranges);

std::pair<std::string, std::string>
make_basic_authentication_header(const std::string &username,
                                 const std::string &password,
                                 bool is_proxy = false);

namespace detail {

#if defined(_WIN64)
inline std::wstring u8string_to_wstring(const char *s) {
  std::wstring ws;
  auto len = static_cast<int>(strlen(s));
  auto wlen = ::MultiByteToWideChar(CP_UTF8, 0, s, len, nullptr, 0);
  if (wlen > 0) {
    ws.resize(wlen);
    wlen = ::MultiByteToWideChar(
        CP_UTF8, 0, s, len,
        const_cast<LPWSTR>(reinterpret_cast<LPCWSTR>(ws.data())), wlen);
    if (wlen != static_cast<int>(ws.size())) { ws.clear(); }
  }
  return ws;
}
#endif

struct FileStat {
  FileStat(const std::string &path);
  bool is_file() const;
  bool is_dir() const;

private:
#if defined(_WIN64)
  struct _stat st_;
#else
  struct stat st_;
#endif
  int ret_ = -1;
};

std::string decode_path(const std::string &s, bool convert_plus_to_space);

std::string trim_copy(const std::string &s);

void divide(
    const char *data, std::size_t size, char d,
    std::function<void(const char *, std::size_t, const char *, std::size_t)>
        fn);

void divide(
    const std::string &str, char d,
    std::function<void(const char *, std::size_t, const char *, std::size_t)>
        fn);

void split(const char *b, const char *e, char d,
           std::function<void(const char *, const char *)> fn);

void split(const char *b, const char *e, char d, size_t m,
           std::function<void(const char *, const char *)> fn);

bool process_client_socket(
    socket_t sock, time_t read_timeout_sec, time_t read_timeout_usec,
    time_t write_timeout_sec, time_t write_timeout_usec,
    time_t max_timeout_msec,
    std::chrono::time_point<std::chrono::steady_clock> start_time,
    std::function<bool(Stream &)> callback);

socket_t create_client_socket(const std::string &host, const std::string &ip,
                              int port, int address_family, bool tcp_nodelay,
                              bool ipv6_v6only, SocketOptions socket_options,
                              time_t connection_timeout_sec,
                              time_t connection_timeout_usec,
                              time_t read_timeout_sec, time_t read_timeout_usec,
                              time_t write_timeout_sec,
                              time_t write_timeout_usec,
                              const std::string &intf, Error &error);

const char *get_header_value(const Headers &headers, const std::string &key,
                             const char *def, size_t id);

std::string params_to_query_str(const Params &params);

void parse_query_text(const char *data, std::size_t size, Params &params);

void parse_query_text(const std::string &s, Params &params);

bool parse_multipart_boundary(const std::string &content_type,
                              std::string &boundary);

bool parse_range_header(const std::string &s, Ranges &ranges);

bool parse_accept_header(const std::string &s,
                         std::vector<std::string> &content_types);

int close_socket(socket_t sock);

ssize_t send_socket(socket_t sock, const void *ptr, size_t size, int flags);

ssize_t read_socket(socket_t sock, void *ptr, size_t size, int flags);

enum class EncodingType { None = 0, Gzip, Brotli, Zstd };

EncodingType encoding_type(const Request &req, const Response &res);

class BufferStream final : public Stream {
public:
  BufferStream() = default;
  ~BufferStream() override = default;

  bool is_readable() const override;
  bool wait_readable() const override;
  bool wait_writable() const override;
  ssize_t read(char *ptr, size_t size) override;
  ssize_t write(const char *ptr, size_t size) override;
  void get_remote_ip_and_port(std::string &ip, int &port) const override;
  void get_local_ip_and_port(std::string &ip, int &port) const override;
  socket_t socket() const override;
  time_t duration() const override;

  const std::string &get_buffer() const;

private:
  std::string buffer;
  size_t position = 0;
};

class compressor {
public:
  virtual ~compressor() = default;

  typedef std::function<bool(const char *data, size_t data_len)> Callback;
  virtual bool compress(const char *data, size_t data_length, bool last,
                        Callback callback) = 0;
};

class decompressor {
public:
  virtual ~decompressor() = default;

  virtual bool is_valid() const = 0;

  typedef std::function<bool(const char *data, size_t data_len)> Callback;
  virtual bool decompress(const char *data, size_t data_length,
                          Callback callback) = 0;
};

class nocompressor final : public compressor {
public:
  ~nocompressor() override = default;

  bool compress(const char *data, size_t data_length, bool /*last*/,
                Callback callback) override;
};

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
class gzip_compressor final : public compressor {
public:
  gzip_compressor();
  ~gzip_compressor() override;

  bool compress(const char *data, size_t data_length, bool last,
                Callback callback) override;

private:
  bool is_valid_ = false;
  z_stream strm_;
};

class gzip_decompressor final : public decompressor {
public:
  gzip_decompressor();
  ~gzip_decompressor() override;

  bool is_valid() const override;

  bool decompress(const char *data, size_t data_length,
                  Callback callback) override;

private:
  bool is_valid_ = false;
  z_stream strm_;
};
#endif

#ifdef CPPHTTPLIB_BROTLI_SUPPORT
class brotli_compressor final : public compressor {
public:
  brotli_compressor();
  ~brotli_compressor();

  bool compress(const char *data, size_t data_length, bool last,
                Callback callback) override;

private:
  BrotliEncoderState *state_ = nullptr;
};

class brotli_decompressor final : public decompressor {
public:
  brotli_decompressor();
  ~brotli_decompressor();

  bool is_valid() const override;

  bool decompress(const char *data, size_t data_length,
                  Callback callback) override;

private:
  BrotliDecoderResult decoder_r;
  BrotliDecoderState *decoder_s = nullptr;
};
#endif

#ifdef CPPHTTPLIB_ZSTD_SUPPORT
class zstd_compressor : public compressor {
public:
  zstd_compressor();
  ~zstd_compressor();

  bool compress(const char *data, size_t data_length, bool last,
                Callback callback) override;

private:
  ZSTD_CCtx *ctx_ = nullptr;
};

class zstd_decompressor : public decompressor {
public:
  zstd_decompressor();
  ~zstd_decompressor();

  bool is_valid() const override;

  bool decompress(const char *data, size_t data_length,
                  Callback callback) override;

private:
  ZSTD_DCtx *ctx_ = nullptr;
};
#endif

// NOTE: until the read size reaches `fixed_buffer_size`, use `fixed_buffer`
// to store data. The call can set memory on stack for performance.
class stream_line_reader {
public:
  stream_line_reader(Stream &strm, char *fixed_buffer,
                     size_t fixed_buffer_size);
  const char *ptr() const;
  size_t size() const;
  bool end_with_crlf() const;
  bool getline();

private:
  void append(char c);

  Stream &strm_;
  char *fixed_buffer_;
  const size_t fixed_buffer_size_;
  size_t fixed_buffer_used_size_ = 0;
  std::string growable_buffer_;
};

class mmap {
public:
  mmap(const char *path);
  ~mmap();

  bool open(const char *path);
  void close();

  bool is_open() const;
  size_t size() const;
  const char *data() const;

private:
#if defined(_WIN64)
  HANDLE hFile_ = NULL;
  HANDLE hMapping_ = NULL;
#else
  int fd_ = -1;
#endif
  size_t size_ = 0;
  void *addr_ = nullptr;
  bool is_open_empty_file = false;
};

// NOTE: https://www.rfc-editor.org/rfc/rfc9110#section-5
namespace fields {

inline bool is_token_char(char c) {
  return std::isalnum(c) || c == '!' || c == '#' || c == '$' || c == '%' ||
         c == '&' || c == '\'' || c == '*' || c == '+' || c == '-' ||
         c == '.' || c == '^' || c == '_' || c == '`' || c == '|' || c == '~';
}

inline bool is_token(const std::string &s) {
  if (s.empty()) { return false; }
  for (auto c : s) {
    if (!is_token_char(c)) { return false; }
  }
  return true;
}

inline bool is_field_name(const std::string &s) { return is_token(s); }

inline bool is_vchar(char c) { return c >= 33 && c <= 126; }

inline bool is_obs_text(char c) { return 128 <= static_cast<unsigned char>(c); }

inline bool is_field_vchar(char c) { return is_vchar(c) || is_obs_text(c); }

inline bool is_field_content(const std::string &s) {
  if (s.empty()) { return true; }

  if (s.size() == 1) {
    return is_field_vchar(s[0]);
  } else if (s.size() == 2) {
    return is_field_vchar(s[0]) && is_field_vchar(s[1]);
  } else {
    size_t i = 0;

    if (!is_field_vchar(s[i])) { return false; }
    i++;

    while (i < s.size() - 1) {
      auto c = s[i++];
      if (c == ' ' || c == '\t' || is_field_vchar(c)) {
      } else {
        return false;
      }
    }

    return is_field_vchar(s[i]);
  }
}

inline bool is_field_value(const std::string &s) { return is_field_content(s); }

} // namespace fields

} // namespace detail

// ----------------------------------------------------------------------------

/*
 * Implementation that will be part of the .cc file if split into .h + .cc.
 */

namespace detail {

inline bool is_hex(char c, int &v) {
  if (0x20 <= c && isdigit(c)) {
    v = c - '0';
    return true;
  } else if ('A' <= c && c <= 'F') {
    v = c - 'A' + 10;
    return true;
  } else if ('a' <= c && c <= 'f') {
    v = c - 'a' + 10;
    return true;
  }
  return false;
}

inline bool from_hex_to_i(const std::string &s, size_t i, size_t cnt,
                          int &val) {
  if (i >= s.size()) { return false; }

  val = 0;
  for (; cnt; i++, cnt--) {
    if (!s[i]) { return false; }
    auto v = 0;
    if (is_hex(s[i], v)) {
      val = val * 16 + v;
    } else {
      return false;
    }
  }
  return true;
}

inline std::string from_i_to_hex(size_t n) {
  static const auto charset = "0123456789abcdef";
  std::string ret;
  do {
    ret = charset[n & 15] + ret;
    n >>= 4;
  } while (n > 0);
  return ret;
}

inline size_t to_utf8(int code, char *buff) {
  if (code < 0x0080) {
    buff[0] = static_cast<char>(code & 0x7F);
    return 1;
  } else if (code < 0x0800) {
    buff[0] = static_cast<char>(0xC0 | ((code >> 6) & 0x1F));
    buff[1] = static_cast<char>(0x80 | (code & 0x3F));
    return 2;
  } else if (code < 0xD800) {
    buff[0] = static_cast<char>(0xE0 | ((code >> 12) & 0xF));
    buff[1] = static_cast<char>(0x80 | ((code >> 6) & 0x3F));
    buff[2] = static_cast<char>(0x80 | (code & 0x3F));
    return 3;
  } else if (code < 0xE000) { // D800 - DFFF is invalid...
    return 0;
  } else if (code < 0x10000) {
    buff[0] = static_cast<char>(0xE0 | ((code >> 12) & 0xF));
    buff[1] = static_cast<char>(0x80 | ((code >> 6) & 0x3F));
    buff[2] = static_cast<char>(0x80 | (code & 0x3F));
    return 3;
  } else if (code < 0x110000) {
    buff[0] = static_cast<char>(0xF0 | ((code >> 18) & 0x7));
    buff[1] = static_cast<char>(0x80 | ((code >> 12) & 0x3F));
    buff[2] = static_cast<char>(0x80 | ((code >> 6) & 0x3F));
    buff[3] = static_cast<char>(0x80 | (code & 0x3F));
    return 4;
  }

  // NOTREACHED
  return 0;
}

// NOTE: This code came up with the following stackoverflow post:
// https://stackoverflow.com/questions/180947/base64-decode-snippet-in-c
inline std::string base64_encode(const std::string &in) {
  static const auto lookup =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  std::string out;
  out.reserve(in.size());

  auto val = 0;
  auto valb = -6;

  for (auto c : in) {
    val = (val << 8) + static_cast<uint8_t>(c);
    valb += 8;
    while (valb >= 0) {
      out.push_back(lookup[(val >> valb) & 0x3F]);
      valb -= 6;
    }
  }

  if (valb > -6) { out.push_back(lookup[((val << 8) >> (valb + 8)) & 0x3F]); }

  while (out.size() % 4) {
    out.push_back('=');
  }

  return out;
}

inline bool is_valid_path(const std::string &path) {
  size_t level = 0;
  size_t i = 0;

  // Skip slash
  while (i < path.size() && path[i] == '/') {
    i++;
  }

  while (i < path.size()) {
    // Read component
    auto beg = i;
    while (i < path.size() && path[i] != '/') {
      if (path[i] == '\0') {
        return false;
      } else if (path[i] == '\\') {
        return false;
      }
      i++;
    }

    auto len = i - beg;
    assert(len > 0);

    if (!path.compare(beg, len, ".")) {
      ;
    } else if (!path.compare(beg, len, "..")) {
      if (level == 0) { return false; }
      level--;
    } else {
      level++;
    }

    // Skip slash
    while (i < path.size() && path[i] == '/') {
      i++;
    }
  }

  return true;
}

inline FileStat::FileStat(const std::string &path) {
#if defined(_WIN64)
  auto wpath = u8string_to_wstring(path.c_str());
  ret_ = _wstat(wpath.c_str(), &st_);
#else
  ret_ = stat(path.c_str(), &st_);
#endif
}
inline bool FileStat::is_file() const {
  return ret_ >= 0 && S_ISREG(st_.st_mode);
}
inline bool FileStat::is_dir() const {
  return ret_ >= 0 && S_ISDIR(st_.st_mode);
}

inline std::string encode_path(const std::string &s) {
  std::string result;
  result.reserve(s.size());

  for (size_t i = 0; s[i]; i++) {
    switch (s[i]) {
    case ' ': result += "%20"; break;
    case '+': result += "%2B"; break;
    case '\r': result += "%0D"; break;
    case '\n': result += "%0A"; break;
    case '\'': result += "%27"; break;
    case ',': result += "%2C"; break;
    // case ':': result += "%3A"; break; // ok? probably...
    case ';': result += "%3B"; break;
    default:
      auto c = static_cast<uint8_t>(s[i]);
      if (c >= 0x80) {
        result += '%';
        char hex[4];
        auto len = snprintf(hex, sizeof(hex) - 1, "%02X", c);
        assert(len == 2);
        result.append(hex, static_cast<size_t>(len));
      } else {
        result += s[i];
      }
      break;
    }
  }

  return result;
}

inline std::string decode_path(const std::string &s,
                               bool convert_plus_to_space) {
  std::string result;

  for (size_t i = 0; i < s.size(); i++) {
    if (s[i] == '%' && i + 1 < s.size()) {
      if (s[i + 1] == 'u') {
        auto val = 0;
        if (from_hex_to_i(s, i + 2, 4, val)) {
          // 4 digits Unicode codes
          char buff[4];
          size_t len = to_utf8(val, buff);
          if (len > 0) { result.append(buff, len); }
          i += 5; // 'u0000'
        } else {
          result += s[i];
        }
      } else {
        auto val = 0;
        if (from_hex_to_i(s, i + 1, 2, val)) {
          // 2 digits hex codes
          result += static_cast<char>(val);
          i += 2; // '00'
        } else {
          result += s[i];
        }
      }
    } else if (convert_plus_to_space && s[i] == '+') {
      result += ' ';
    } else {
      result += s[i];
    }
  }

  return result;
}

inline std::string file_extension(const std::string &path) {
  std::smatch m;
  thread_local auto re = std::regex("\\.([a-zA-Z0-9]+)$");
  if (std::regex_search(path, m, re)) { return m[1].str(); }
  return std::string();
}

inline bool is_space_or_tab(char c) { return c == ' ' || c == '\t'; }

inline std::pair<size_t, size_t> trim(const char *b, const char *e, size_t left,
                                      size_t right) {
  while (b + left < e && is_space_or_tab(b[left])) {
    left++;
  }
  while (right > 0 && is_space_or_tab(b[right - 1])) {
    right--;
  }
  return std::make_pair(left, right);
}

inline std::string trim_copy(const std::string &s) {
  auto r = trim(s.data(), s.data() + s.size(), 0, s.size());
  return s.substr(r.first, r.second - r.first);
}

inline std::string trim_double_quotes_copy(const std::string &s) {
  if (s.length() >= 2 && s.front() == '"' && s.back() == '"') {
    return s.substr(1, s.size() - 2);
  }
  return s;
}

inline void
divide(const char *data, std::size_t size, char d,
       std::function<void(const char *, std::size_t, const char *, std::size_t)>
           fn) {
  const auto it = std::find(data, data + size, d);
  const auto found = static_cast<std::size_t>(it != data + size);
  const auto lhs_data = data;
  const auto lhs_size = static_cast<std::size_t>(it - data);
  const auto rhs_data = it + found;
  const auto rhs_size = size - lhs_size - found;

  fn(lhs_data, lhs_size, rhs_data, rhs_size);
}

inline void
divide(const std::string &str, char d,
       std::function<void(const char *, std::size_t, const char *, std::size_t)>
           fn) {
  divide(str.data(), str.size(), d, std::move(fn));
}

inline void split(const char *b, const char *e, char d,
                  std::function<void(const char *, const char *)> fn) {
  return split(b, e, d, (std::numeric_limits<size_t>::max)(), std::move(fn));
}

inline void split(const char *b, const char *e, char d, size_t m,
                  std::function<void(const char *, const char *)> fn) {
  size_t i = 0;
  size_t beg = 0;
  size_t count = 1;

  while (e ? (b + i < e) : (b[i] != '\0')) {
    if (b[i] == d && count < m) {
      auto r = trim(b, e, beg, i);
      if (r.first < r.second) { fn(&b[r.first], &b[r.second]); }
      beg = i + 1;
      count++;
    }
    i++;
  }

  if (i) {
    auto r = trim(b, e, beg, i);
    if (r.first < r.second) { fn(&b[r.first], &b[r.second]); }
  }
}

inline stream_line_reader::stream_line_reader(Stream &strm, char *fixed_buffer,
                                              size_t fixed_buffer_size)
    : strm_(strm), fixed_buffer_(fixed_buffer),
      fixed_buffer_size_(fixed_buffer_size) {}

inline const char *stream_line_reader::ptr() const {
  if (growable_buffer_.empty()) {
    return fixed_buffer_;
  } else {
    return growable_buffer_.data();
  }
}

inline size_t stream_line_reader::size() const {
  if (growable_buffer_.empty()) {
    return fixed_buffer_used_size_;
  } else {
    return growable_buffer_.size();
  }
}

inline bool stream_line_reader::end_with_crlf() const {
  auto end = ptr() + size();
  return size() >= 2 && end[-2] == '\r' && end[-1] == '\n';
}

inline bool stream_line_reader::getline() {
  fixed_buffer_used_size_ = 0;
  growable_buffer_.clear();

#ifndef CPPHTTPLIB_ALLOW_LF_AS_LINE_TERMINATOR
  char prev_byte = 0;
#endif

  for (size_t i = 0;; i++) {
    if (size() >= CPPHTTPLIB_MAX_LINE_LENGTH) {
      // Treat exceptionally long lines as an error to
      // prevent infinite loops/memory exhaustion
      return false;
    }
    char byte;
    auto n = strm_.read(&byte, 1);

    if (n < 0) {
      return false;
    } else if (n == 0) {
      if (i == 0) {
        return false;
      } else {
        break;
      }
    }

    append(byte);

#ifdef CPPHTTPLIB_ALLOW_LF_AS_LINE_TERMINATOR
    if (byte == '\n') { break; }
#else
    if (prev_byte == '\r' && byte == '\n') { break; }
    prev_byte = byte;
#endif
  }

  return true;
}

inline void stream_line_reader::append(char c) {
  if (fixed_buffer_used_size_ < fixed_buffer_size_ - 1) {
    fixed_buffer_[fixed_buffer_used_size_++] = c;
    fixed_buffer_[fixed_buffer_used_size_] = '\0';
  } else {
    if (growable_buffer_.empty()) {
      assert(fixed_buffer_[fixed_buffer_used_size_] == '\0');
      growable_buffer_.assign(fixed_buffer_, fixed_buffer_used_size_);
    }
    growable_buffer_ += c;
  }
}

inline mmap::mmap(const char *path) { open(path); }

inline mmap::~mmap() { close(); }

inline bool mmap::open(const char *path) {
  close();

#if defined(_WIN64)
  auto wpath = u8string_to_wstring(path);
  if (wpath.empty()) { return false; }

  hFile_ = ::CreateFile2(wpath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                         OPEN_EXISTING, NULL);

  if (hFile_ == INVALID_HANDLE_VALUE) { return false; }

  LARGE_INTEGER size{};
  if (!::GetFileSizeEx(hFile_, &size)) { return false; }
  // If the following line doesn't compile due to QuadPart, update Windows SDK.
  // See:
  // https://github.com/yhirose/cpp-httplib/issues/1903#issuecomment-2316520721
  if (static_cast<ULONGLONG>(size.QuadPart) >
      (std::numeric_limits<decltype(size_)>::max)()) {
    // `size_t` might be 32-bits, on 32-bits Windows.
    return false;
  }
  size_ = static_cast<size_t>(size.QuadPart);

  hMapping_ =
      ::CreateFileMappingFromApp(hFile_, NULL, PAGE_READONLY, size_, NULL);

  // Special treatment for an empty file...
  if (hMapping_ == NULL && size_ == 0) {
    close();
    is_open_empty_file = true;
    return true;
  }

  if (hMapping_ == NULL) {
    close();
    return false;
  }

  addr_ = ::MapViewOfFileFromApp(hMapping_, FILE_MAP_READ, 0, 0);

  if (addr_ == nullptr) {
    close();
    return false;
  }
#else
  fd_ = ::open(path, O_RDONLY);
  if (fd_ == -1) { return false; }

  struct stat sb;
  if (fstat(fd_, &sb) == -1) {
    close();
    return false;
  }
  size_ = static_cast<size_t>(sb.st_size);

  addr_ = ::mmap(NULL, size_, PROT_READ, MAP_PRIVATE, fd_, 0);

  // Special treatment for an empty file...
  if (addr_ == MAP_FAILED && size_ == 0) {
    close();
    is_open_empty_file = true;
    return false;
  }
#endif

  return true;
}

inline bool mmap::is_open() const {
  return is_open_empty_file ? true : addr_ != nullptr;
}

inline size_t mmap::size() const { return size_; }

inline const char *mmap::data() const {
  return is_open_empty_file ? "" : static_cast<const char *>(addr_);
}

inline void mmap::close() {
#if defined(_WIN64)
  if (addr_) {
    ::UnmapViewOfFile(addr_);
    addr_ = nullptr;
  }

  if (hMapping_) {
    ::CloseHandle(hMapping_);
    hMapping_ = NULL;
  }

  if (hFile_ != INVALID_HANDLE_VALUE) {
    ::CloseHandle(hFile_);
    hFile_ = INVALID_HANDLE_VALUE;
  }

  is_open_empty_file = false;
#else
  if (addr_ != nullptr) {
    munmap(addr_, size_);
    addr_ = nullptr;
  }

  if (fd_ != -1) {
    ::close(fd_);
    fd_ = -1;
  }
#endif
  size_ = 0;
}
inline int close_socket(socket_t sock) {
#ifdef _WIN64
  return closesocket(sock);
#else
  return close(sock);
#endif
}

template <typename T> inline ssize_t handle_EINTR(T fn) {
  ssize_t res = 0;
  while (true) {
    res = fn();
    if (res < 0 && errno == EINTR) {
      std::this_thread::sleep_for(std::chrono::microseconds{1});
      continue;
    }
    break;
  }
  return res;
}

inline ssize_t read_socket(socket_t sock, void *ptr, size_t size, int flags) {
  return handle_EINTR([&]() {
    return recv(sock,
#ifdef _WIN64
                static_cast<char *>(ptr), static_cast<int>(size),
#else
                ptr, size,
#endif
                flags);
  });
}

inline ssize_t send_socket(socket_t sock, const void *ptr, size_t size,
                           int flags) {
  return handle_EINTR([&]() {
    return send(sock,
#ifdef _WIN64
                static_cast<const char *>(ptr), static_cast<int>(size),
#else
                ptr, size,
#endif
                flags);
  });
}

inline int poll_wrapper(struct pollfd *fds, nfds_t nfds, int timeout) {
#ifdef _WIN64
  return ::WSAPoll(fds, nfds, timeout);
#else
  return ::poll(fds, nfds, timeout);
#endif
}

template <bool Read>
inline ssize_t select_impl(socket_t sock, time_t sec, time_t usec) {
#ifdef __APPLE__
  if (sock >= FD_SETSIZE) { return -1; }

  fd_set fds, *rfds, *wfds;
  FD_ZERO(&fds);
  FD_SET(sock, &fds);
  rfds = (Read ? &fds : nullptr);
  wfds = (Read ? nullptr : &fds);

  timeval tv;
  tv.tv_sec = static_cast<long>(sec);
  tv.tv_usec = static_cast<decltype(tv.tv_usec)>(usec);

  return handle_EINTR([&]() {
    return select(static_cast<int>(sock + 1), rfds, wfds, nullptr, &tv);
  });
#else
  struct pollfd pfd;
  pfd.fd = sock;
  pfd.events = (Read ? POLLIN : POLLOUT);

  auto timeout = static_cast<int>(sec * 1000 + usec / 1000);

  return handle_EINTR([&]() { return poll_wrapper(&pfd, 1, timeout); });
#endif
}

inline ssize_t select_read(socket_t sock, time_t sec, time_t usec) {
  return select_impl<true>(sock, sec, usec);
}

inline ssize_t select_write(socket_t sock, time_t sec, time_t usec) {
  return select_impl<false>(sock, sec, usec);
}

inline Error wait_until_socket_is_ready(socket_t sock, time_t sec,
                                        time_t usec) {
#ifdef __APPLE__
  if (sock >= FD_SETSIZE) { return Error::Connection; }

  fd_set fdsr, fdsw;
  FD_ZERO(&fdsr);
  FD_ZERO(&fdsw);
  FD_SET(sock, &fdsr);
  FD_SET(sock, &fdsw);

  timeval tv;
  tv.tv_sec = static_cast<long>(sec);
  tv.tv_usec = static_cast<decltype(tv.tv_usec)>(usec);

  auto ret = handle_EINTR([&]() {
    return select(static_cast<int>(sock + 1), &fdsr, &fdsw, nullptr, &tv);
  });

  if (ret == 0) { return Error::ConnectionTimeout; }

  if (ret > 0 && (FD_ISSET(sock, &fdsr) || FD_ISSET(sock, &fdsw))) {
    auto error = 0;
    socklen_t len = sizeof(error);
    auto res = getsockopt(sock, SOL_SOCKET, SO_ERROR,
                          reinterpret_cast<char *>(&error), &len);
    auto successful = res >= 0 && !error;
    return successful ? Error::Success : Error::Connection;
  }

  return Error::Connection;
#else
  struct pollfd pfd_read;
  pfd_read.fd = sock;
  pfd_read.events = POLLIN | POLLOUT;

  auto timeout = static_cast<int>(sec * 1000 + usec / 1000);

  auto poll_res =
      handle_EINTR([&]() { return poll_wrapper(&pfd_read, 1, timeout); });

  if (poll_res == 0) { return Error::ConnectionTimeout; }

  if (poll_res > 0 && pfd_read.revents & (POLLIN | POLLOUT)) {
    auto error = 0;
    socklen_t len = sizeof(error);
    auto res = getsockopt(sock, SOL_SOCKET, SO_ERROR,
                          reinterpret_cast<char *>(&error), &len);
    auto successful = res >= 0 && !error;
    return successful ? Error::Success : Error::Connection;
  }

  return Error::Connection;
#endif
}

inline bool is_socket_alive(socket_t sock) {
  const auto val = detail::select_read(sock, 0, 0);
  if (val == 0) {
    return true;
  } else if (val < 0 && errno == EBADF) {
    return false;
  }
  char buf[1];
  return detail::read_socket(sock, &buf[0], sizeof(buf), MSG_PEEK) > 0;
}

class SocketStream final : public Stream {
public:
  SocketStream(socket_t sock, time_t read_timeout_sec, time_t read_timeout_usec,
               time_t write_timeout_sec, time_t write_timeout_usec,
               time_t max_timeout_msec = 0,
               std::chrono::time_point<std::chrono::steady_clock> start_time =
                   (std::chrono::steady_clock::time_point::min)());
  ~SocketStream() override;

  bool is_readable() const override;
  bool wait_readable() const override;
  bool wait_writable() const override;
  ssize_t read(char *ptr, size_t size) override;
  ssize_t write(const char *ptr, size_t size) override;
  void get_remote_ip_and_port(std::string &ip, int &port) const override;
  void get_local_ip_and_port(std::string &ip, int &port) const override;
  socket_t socket() const override;
  time_t duration() const override;

private:
  socket_t sock_;
  time_t read_timeout_sec_;
  time_t read_timeout_usec_;
  time_t write_timeout_sec_;
  time_t write_timeout_usec_;
  time_t max_timeout_msec_;
  const std::chrono::time_point<std::chrono::steady_clock> start_time_;

  std::vector<char> read_buff_;
  size_t read_buff_off_ = 0;
  size_t read_buff_content_size_ = 0;

  static const size_t read_buff_size_ = 1024l * 4;
};

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
class SSLSocketStream final : public Stream {
public:
  SSLSocketStream(
      socket_t sock, SSL *ssl, time_t read_timeout_sec,
      time_t read_timeout_usec, time_t write_timeout_sec,
      time_t write_timeout_usec, time_t max_timeout_msec = 0,
      std::chrono::time_point<std::chrono::steady_clock> start_time =
          (std::chrono::steady_clock::time_point::min)());
  ~SSLSocketStream() override;

  bool is_readable() const override;
  bool wait_readable() const override;
  bool wait_writable() const override;
  ssize_t read(char *ptr, size_t size) override;
  ssize_t write(const char *ptr, size_t size) override;
  void get_remote_ip_and_port(std::string &ip, int &port) const override;
  void get_local_ip_and_port(std::string &ip, int &port) const override;
  socket_t socket() const override;
  time_t duration() const override;

private:
  socket_t sock_;
  SSL *ssl_;
  time_t read_timeout_sec_;
  time_t read_timeout_usec_;
  time_t write_timeout_sec_;
  time_t write_timeout_usec_;
  time_t max_timeout_msec_;
  const std::chrono::time_point<std::chrono::steady_clock> start_time_;
};
#endif

inline bool keep_alive(const std::atomic<socket_t> &svr_sock, socket_t sock,
                       time_t keep_alive_timeout_sec) {
  using namespace std::chrono;

  const auto interval_usec =
      CPPHTTPLIB_KEEPALIVE_TIMEOUT_CHECK_INTERVAL_USECOND;

  // Avoid expensive `steady_clock::now()` call for the first time
  if (select_read(sock, 0, interval_usec) > 0) { return true; }

  const auto start = steady_clock::now() - microseconds{interval_usec};
  const auto timeout = seconds{keep_alive_timeout_sec};

  while (true) {
    if (svr_sock == INVALID_SOCKET) {
      break; // Server socket is closed
    }

    auto val = select_read(sock, 0, interval_usec);
    if (val < 0) {
      break; // Ssocket error
    } else if (val == 0) {
      if (steady_clock::now() - start > timeout) {
        break; // Timeout
      }
    } else {
      return true; // Ready for read
    }
  }

  return false;
}

template <typename T>
inline bool
process_server_socket_core(const std::atomic<socket_t> &svr_sock, socket_t sock,
                           size_t keep_alive_max_count,
                           time_t keep_alive_timeout_sec, T callback) {
  assert(keep_alive_max_count > 0);
  auto ret = false;
  auto count = keep_alive_max_count;
  while (count > 0 && keep_alive(svr_sock, sock, keep_alive_timeout_sec)) {
    auto close_connection = count == 1;
    auto connection_closed = false;
    ret = callback(close_connection, connection_closed);
    if (!ret || connection_closed) { break; }
    count--;
  }
  return ret;
}

template <typename T>
inline bool
process_server_socket(const std::atomic<socket_t> &svr_sock, socket_t sock,
                      size_t keep_alive_max_count,
                      time_t keep_alive_timeout_sec, time_t read_timeout_sec,
                      time_t read_timeout_usec, time_t write_timeout_sec,
                      time_t write_timeout_usec, T callback) {
  return process_server_socket_core(
      svr_sock, sock, keep_alive_max_count, keep_alive_timeout_sec,
      [&](bool close_connection, bool &connection_closed) {
        SocketStream strm(sock, read_timeout_sec, read_timeout_usec,
                          write_timeout_sec, write_timeout_usec);
        return callback(strm, close_connection, connection_closed);
      });
}

inline bool process_client_socket(
    socket_t sock, time_t read_timeout_sec, time_t read_timeout_usec,
    time_t write_timeout_sec, time_t write_timeout_usec,
    time_t max_timeout_msec,
    std::chrono::time_point<std::chrono::steady_clock> start_time,
    std::function<bool(Stream &)> callback) {
  SocketStream strm(sock, read_timeout_sec, read_timeout_usec,
                    write_timeout_sec, write_timeout_usec, max_timeout_msec,
                    start_time);
  return callback(strm);
}

inline int shutdown_socket(socket_t sock) {
#ifdef _WIN64
  return shutdown(sock, SD_BOTH);
#else
  return shutdown(sock, SHUT_RDWR);
#endif
}

inline std::string escape_abstract_namespace_unix_domain(const std::string &s) {
  if (s.size() > 1 && s[0] == '\0') {
    auto ret = s;
    ret[0] = '@';
    return ret;
  }
  return s;
}

inline std::string
unescape_abstract_namespace_unix_domain(const std::string &s) {
  if (s.size() > 1 && s[0] == '@') {
    auto ret = s;
    ret[0] = '\0';
    return ret;
  }
  return s;
}

inline int getaddrinfo_with_timeout(const char *node, const char *service,
                                    const struct addrinfo *hints,
                                    struct addrinfo **res, time_t timeout_sec) {
#ifdef CPPHTTPLIB_USE_NON_BLOCKING_GETADDRINFO
  if (timeout_sec <= 0) {
    // No timeout specified, use standard getaddrinfo
    return getaddrinfo(node, service, hints, res);
  }

#ifdef _WIN64
  // Windows-specific implementation using GetAddrInfoEx with overlapped I/O
  OVERLAPPED overlapped = {0};
  HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!event) { return EAI_FAIL; }

  overlapped.hEvent = event;

  PADDRINFOEXW result_addrinfo = nullptr;
  HANDLE cancel_handle = nullptr;

  ADDRINFOEXW hints_ex = {0};
  if (hints) {
    hints_ex.ai_flags = hints->ai_flags;
    hints_ex.ai_family = hints->ai_family;
    hints_ex.ai_socktype = hints->ai_socktype;
    hints_ex.ai_protocol = hints->ai_protocol;
  }

  auto wnode = u8string_to_wstring(node);
  auto wservice = u8string_to_wstring(service);

  auto ret = ::GetAddrInfoExW(wnode.data(), wservice.data(), NS_DNS, nullptr,
                              hints ? &hints_ex : nullptr, &result_addrinfo,
                              nullptr, &overlapped, nullptr, &cancel_handle);

  if (ret == WSA_IO_PENDING) {
    auto wait_result =
        ::WaitForSingleObject(event, static_cast<DWORD>(timeout_sec * 1000));
    if (wait_result == WAIT_TIMEOUT) {
      if (cancel_handle) { ::GetAddrInfoExCancel(&cancel_handle); }
      ::CloseHandle(event);
      return EAI_AGAIN;
    }

    DWORD bytes_returned;
    if (!::GetOverlappedResult((HANDLE)INVALID_SOCKET, &overlapped,
                               &bytes_returned, FALSE)) {
      ::CloseHandle(event);
      return ::WSAGetLastError();
    }
  }

  ::CloseHandle(event);

  if (ret == NO_ERROR || ret == WSA_IO_PENDING) {
    *res = reinterpret_cast<struct addrinfo *>(result_addrinfo);
    return 0;
  }

  return ret;
#elif defined(TARGET_OS_OSX)
  // macOS implementation using CFHost API for asynchronous DNS resolution
  CFStringRef hostname_ref = CFStringCreateWithCString(
      kCFAllocatorDefault, node, kCFStringEncodingUTF8);
  if (!hostname_ref) { return EAI_MEMORY; }

  CFHostRef host_ref = CFHostCreateWithName(kCFAllocatorDefault, hostname_ref);
  CFRelease(hostname_ref);
  if (!host_ref) { return EAI_MEMORY; }

  // Set up context for callback
  struct CFHostContext {
    bool completed = false;
    bool success = false;
    CFArrayRef addresses = nullptr;
    std::mutex mutex;
    std::condition_variable cv;
  } context;

  CFHostClientContext client_context;
  memset(&client_context, 0, sizeof(client_context));
  client_context.info = &context;

  // Set callback
  auto callback = [](CFHostRef theHost, CFHostInfoType /*typeInfo*/,
                     const CFStreamError *error, void *info) {
    auto ctx = static_cast<CFHostContext *>(info);
    std::lock_guard<std::mutex> lock(ctx->mutex);

    if (error && error->error != 0) {
      ctx->success = false;
    } else {
      Boolean hasBeenResolved;
      ctx->addresses = CFHostGetAddressing(theHost, &hasBeenResolved);
      if (ctx->addresses && hasBeenResolved) {
        CFRetain(ctx->addresses);
        ctx->success = true;
      } else {
        ctx->success = false;
      }
    }
    ctx->completed = true;
    ctx->cv.notify_one();
  };

  if (!CFHostSetClient(host_ref, callback, &client_context)) {
    CFRelease(host_ref);
    return EAI_SYSTEM;
  }

  // Schedule on run loop
  CFRunLoopRef run_loop = CFRunLoopGetCurrent();
  CFHostScheduleWithRunLoop(host_ref, run_loop, kCFRunLoopDefaultMode);

  // Start resolution
  CFStreamError stream_error;
  if (!CFHostStartInfoResolution(host_ref, kCFHostAddresses, &stream_error)) {
    CFHostUnscheduleFromRunLoop(host_ref, run_loop, kCFRunLoopDefaultMode);
    CFRelease(host_ref);
    return EAI_FAIL;
  }

  // Wait for completion with timeout
  auto timeout_time =
      std::chrono::steady_clock::now() + std::chrono::seconds(timeout_sec);
  bool timed_out = false;

  {
    std::unique_lock<std::mutex> lock(context.mutex);

    while (!context.completed) {
      auto now = std::chrono::steady_clock::now();
      if (now >= timeout_time) {
        timed_out = true;
        break;
      }

      // Run the runloop for a short time
      lock.unlock();
      CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.1, true);
      lock.lock();
    }
  }

  // Clean up
  CFHostUnscheduleFromRunLoop(host_ref, run_loop, kCFRunLoopDefaultMode);
  CFHostSetClient(host_ref, nullptr, nullptr);

  if (timed_out || !context.completed) {
    CFHostCancelInfoResolution(host_ref, kCFHostAddresses);
    CFRelease(host_ref);
    return EAI_AGAIN;
  }

  if (!context.success || !context.addresses) {
    CFRelease(host_ref);
    return EAI_NODATA;
  }

  // Convert CFArray to addrinfo
  CFIndex count = CFArrayGetCount(context.addresses);
  if (count == 0) {
    CFRelease(context.addresses);
    CFRelease(host_ref);
    return EAI_NODATA;
  }

  struct addrinfo *result_addrinfo = nullptr;
  struct addrinfo **current = &result_addrinfo;

  for (CFIndex i = 0; i < count; i++) {
    CFDataRef addr_data =
        static_cast<CFDataRef>(CFArrayGetValueAtIndex(context.addresses, i));
    if (!addr_data) continue;

    const struct sockaddr *sockaddr_ptr =
        reinterpret_cast<const struct sockaddr *>(CFDataGetBytePtr(addr_data));
    socklen_t sockaddr_len = static_cast<socklen_t>(CFDataGetLength(addr_data));

    // Allocate addrinfo structure
    *current = static_cast<struct addrinfo *>(malloc(sizeof(struct addrinfo)));
    if (!*current) {
      freeaddrinfo(result_addrinfo);
      CFRelease(context.addresses);
      CFRelease(host_ref);
      return EAI_MEMORY;
    }

    memset(*current, 0, sizeof(struct addrinfo));

    // Set up addrinfo fields
    (*current)->ai_family = sockaddr_ptr->sa_family;
    (*current)->ai_socktype = hints ? hints->ai_socktype : SOCK_STREAM;
    (*current)->ai_protocol = hints ? hints->ai_protocol : IPPROTO_TCP;
    (*current)->ai_addrlen = sockaddr_len;

    // Copy sockaddr
    (*current)->ai_addr = static_cast<struct sockaddr *>(malloc(sockaddr_len));
    if (!(*current)->ai_addr) {
      freeaddrinfo(result_addrinfo);
      CFRelease(context.addresses);
      CFRelease(host_ref);
      return EAI_MEMORY;
    }
    memcpy((*current)->ai_addr, sockaddr_ptr, sockaddr_len);

    // Set port if service is specified
    if (service && strlen(service) > 0) {
      int port = atoi(service);
      if (port > 0) {
        if (sockaddr_ptr->sa_family == AF_INET) {
          reinterpret_cast<struct sockaddr_in *>((*current)->ai_addr)
              ->sin_port = htons(static_cast<uint16_t>(port));
        } else if (sockaddr_ptr->sa_family == AF_INET6) {
          reinterpret_cast<struct sockaddr_in6 *>((*current)->ai_addr)
              ->sin6_port = htons(static_cast<uint16_t>(port));
        }
      }
    }

    current = &((*current)->ai_next);
  }

  CFRelease(context.addresses);
  CFRelease(host_ref);

  *res = result_addrinfo;
  return 0;
#elif defined(_GNU_SOURCE) && defined(__GLIBC__) &&                            \
    (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 2))
  // Linux implementation using getaddrinfo_a for asynchronous DNS resolution
  struct gaicb request;
  struct gaicb *requests[1] = {&request};
  struct sigevent sevp;
  struct timespec timeout;

  // Initialize the request structure
  memset(&request, 0, sizeof(request));
  request.ar_name = node;
  request.ar_service = service;
  request.ar_request = hints;

  // Set up timeout
  timeout.tv_sec = timeout_sec;
  timeout.tv_nsec = 0;

  // Initialize sigevent structure (not used, but required)
  memset(&sevp, 0, sizeof(sevp));
  sevp.sigev_notify = SIGEV_NONE;

  // Start asynchronous resolution
  int start_result = getaddrinfo_a(GAI_NOWAIT, requests, 1, &sevp);
  if (start_result != 0) { return start_result; }

  // Wait for completion with timeout
  int wait_result =
      gai_suspend((const struct gaicb *const *)requests, 1, &timeout);

  if (wait_result == 0) {
    // Completed successfully, get the result
    int gai_result = gai_error(&request);
    if (gai_result == 0) {
      *res = request.ar_result;
      return 0;
    } else {
      // Clean up on error
      if (request.ar_result) { freeaddrinfo(request.ar_result); }
      return gai_result;
    }
  } else if (wait_result == EAI_AGAIN) {
    // Timeout occurred, cancel the request
    gai_cancel(&request);
    return EAI_AGAIN;
  } else {
    // Other error occurred
    gai_cancel(&request);
    return wait_result;
  }
#else
  // Fallback implementation using thread-based timeout for other Unix systems
  std::mutex result_mutex;
  std::condition_variable result_cv;
  auto completed = false;
  auto result = EAI_SYSTEM;
  struct addrinfo *result_addrinfo = nullptr;

  std::thread resolve_thread([&]() {
    auto thread_result = getaddrinfo(node, service, hints, &result_addrinfo);

    std::lock_guard<std::mutex> lock(result_mutex);
    result = thread_result;
    completed = true;
    result_cv.notify_one();
  });

  // Wait for completion or timeout
  std::unique_lock<std::mutex> lock(result_mutex);
  auto finished = result_cv.wait_for(lock, std::chrono::seconds(timeout_sec),
                                     [&] { return completed; });

  if (finished) {
    // Operation completed within timeout
    resolve_thread.join();
    *res = result_addrinfo;
    return result;
  } else {
    // Timeout occurred
    resolve_thread.detach(); // Let the thread finish in background
    return EAI_AGAIN;        // Return timeout error
  }
#endif
#else
  (void)(timeout_sec); // Unused parameter for non-blocking getaddrinfo
  return getaddrinfo(node, service, hints, res);
#endif
}

template <typename BindOrConnect>
socket_t create_socket(const std::string &host, const std::string &ip, int port,
                       int address_family, int socket_flags, bool tcp_nodelay,
                       bool ipv6_v6only, SocketOptions socket_options,
                       BindOrConnect bind_or_connect, time_t timeout_sec = 0) {
  // Get address info
  const char *node = nullptr;
  struct addrinfo hints;
  struct addrinfo *result;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_IP;

  if (!ip.empty()) {
    node = ip.c_str();
    // Ask getaddrinfo to convert IP in c-string to address
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_NUMERICHOST;
  } else {
    if (!host.empty()) { node = host.c_str(); }
    hints.ai_family = address_family;
    hints.ai_flags = socket_flags;
  }

#if !defined(_WIN64) || defined(CPPHTTPLIB_HAVE_AFUNIX_H)
  if (hints.ai_family == AF_UNIX) {
    const auto addrlen = host.length();
    if (addrlen > sizeof(sockaddr_un::sun_path)) { return INVALID_SOCKET; }

#ifdef SOCK_CLOEXEC
    auto sock = socket(hints.ai_family, hints.ai_socktype | SOCK_CLOEXEC,
                       hints.ai_protocol);
#else
    auto sock = socket(hints.ai_family, hints.ai_socktype, hints.ai_protocol);
#endif

    if (sock != INVALID_SOCKET) {
      sockaddr_un addr{};
      addr.sun_family = AF_UNIX;

      auto unescaped_host = unescape_abstract_namespace_unix_domain(host);
      std::copy(unescaped_host.begin(), unescaped_host.end(), addr.sun_path);

      hints.ai_addr = reinterpret_cast<sockaddr *>(&addr);
      hints.ai_addrlen = static_cast<socklen_t>(
          sizeof(addr) - sizeof(addr.sun_path) + addrlen);

#ifndef SOCK_CLOEXEC
#ifndef _WIN64
      fcntl(sock, F_SETFD, FD_CLOEXEC);
#endif
#endif

      if (socket_options) { socket_options(sock); }

#ifdef _WIN64
      // Setting SO_REUSEADDR seems not to work well with AF_UNIX on windows, so
      // remove the option.
      detail::set_socket_opt(sock, SOL_SOCKET, SO_REUSEADDR, 0);
#endif

      bool dummy;
      if (!bind_or_connect(sock, hints, dummy)) {
        close_socket(sock);
        sock = INVALID_SOCKET;
      }
    }
    return sock;
  }
#endif

  auto service = std::to_string(port);

  if (getaddrinfo_with_timeout(node, service.c_str(), &hints, &result,
                               timeout_sec)) {
#if defined __linux__ && !defined __ANDROID__
    res_init();
#endif
    return INVALID_SOCKET;
  }
  auto se = detail::scope_exit([&] { freeaddrinfo(result); });

  for (auto rp = result; rp; rp = rp->ai_next) {
    // Create a socket
#ifdef _WIN64
    auto sock =
        WSASocketW(rp->ai_family, rp->ai_socktype, rp->ai_protocol, nullptr, 0,
                   WSA_FLAG_NO_HANDLE_INHERIT | WSA_FLAG_OVERLAPPED);
    /**
     * Since the WSA_FLAG_NO_HANDLE_INHERIT is only supported on Windows 7 SP1
     * and above the socket creation fails on older Windows Systems.
     *
     * Let's try to create a socket the old way in this case.
     *
     * Reference:
     * https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-w
sasocketa
     *
     * WSA_FLAG_NO_HANDLE_INHERIT:
     * This flag is supported on Windows 7 with SP1, Windows Server 2008 R2 with
     * SP1, and later
     *
     */
    if (sock == INVALID_SOCKET) {
      sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    }
#else

#ifdef SOCK_CLOEXEC
    auto sock =
        socket(rp->ai_family, rp->ai_socktype | SOCK_CLOEXEC, rp->ai_protocol);
#else
    auto sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
#endif

#endif
    if (sock == INVALID_SOCKET) { continue; }

#if !defined _WIN64 && !defined SOCK_CLOEXEC
    if (fcntl(sock, F_SETFD, FD_CLOEXEC) == -1) {
      close_socket(sock);
      continue;
    }
#endif

    if (tcp_nodelay) { set_socket_opt(sock, IPPROTO_TCP, TCP_NODELAY, 1); }

    if (rp->ai_family == AF_INET6) {
      set_socket_opt(sock, IPPROTO_IPV6, IPV6_V6ONLY, ipv6_v6only ? 1 : 0);
    }

    if (socket_options) { socket_options(sock); }

    // bind or connect
    auto quit = false;
    if (bind_or_connect(sock, *rp, quit)) { return sock; }

    close_socket(sock);

    if (quit) { break; }
  }

  return INVALID_SOCKET;
}

inline void set_nonblocking(socket_t sock, bool nonblocking) {
#ifdef _WIN64
  auto flags = nonblocking ? 1UL : 0UL;
  ioctlsocket(sock, FIONBIO, &flags);
#else
  auto flags = fcntl(sock, F_GETFL, 0);
  fcntl(sock, F_SETFL,
        nonblocking ? (flags | O_NONBLOCK) : (flags & (~O_NONBLOCK)));
#endif
}

inline bool is_connection_error() {
#ifdef _WIN64
  return WSAGetLastError() != WSAEWOULDBLOCK;
#else
  return errno != EINPROGRESS;
#endif
}

inline bool bind_ip_address(socket_t sock, const std::string &host) {
  struct addrinfo hints;
  struct addrinfo *result;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;

  if (getaddrinfo_with_timeout(host.c_str(), "0", &hints, &result, 0)) {
    return false;
  }

  auto se = detail::scope_exit([&] { freeaddrinfo(result); });

  auto ret = false;
  for (auto rp = result; rp; rp = rp->ai_next) {
    const auto &ai = *rp;
    if (!::bind(sock, ai.ai_addr, static_cast<socklen_t>(ai.ai_addrlen))) {
      ret = true;
      break;
    }
  }

  return ret;
}

#if !defined _WIN64 && !defined ANDROID && !defined _AIX && !defined __MVS__
#define USE_IF2IP
#endif

#ifdef USE_IF2IP
inline std::string if2ip(int address_family, const std::string &ifn) {
  struct ifaddrs *ifap;
  getifaddrs(&ifap);
  auto se = detail::scope_exit([&] { freeifaddrs(ifap); });

  std::string addr_candidate;
  for (auto ifa = ifap; ifa; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr && ifn == ifa->ifa_name &&
        (AF_UNSPEC == address_family ||
         ifa->ifa_addr->sa_family == address_family)) {
      if (ifa->ifa_addr->sa_family == AF_INET) {
        auto sa = reinterpret_cast<struct sockaddr_in *>(ifa->ifa_addr);
        char buf[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &sa->sin_addr, buf, INET_ADDRSTRLEN)) {
          return std::string(buf, INET_ADDRSTRLEN);
        }
      } else if (ifa->ifa_addr->sa_family == AF_INET6) {
        auto sa = reinterpret_cast<struct sockaddr_in6 *>(ifa->ifa_addr);
        if (!IN6_IS_ADDR_LINKLOCAL(&sa->sin6_addr)) {
          char buf[INET6_ADDRSTRLEN] = {};
          if (inet_ntop(AF_INET6, &sa->sin6_addr, buf, INET6_ADDRSTRLEN)) {
            // equivalent to mac's IN6_IS_ADDR_UNIQUE_LOCAL
            auto s6_addr_head = sa->sin6_addr.s6_addr[0];
            if (s6_addr_head == 0xfc || s6_addr_head == 0xfd) {
              addr_candidate = std::string(buf, INET6_ADDRSTRLEN);
            } else {
              return std::string(buf, INET6_ADDRSTRLEN);
            }
          }
        }
      }
    }
  }
  return addr_candidate;
}
#endif

inline socket_t create_client_socket(
    const std::string &host, const std::string &ip, int port,
    int address_family, bool tcp_nodelay, bool ipv6_v6only,
    SocketOptions socket_options, time_t connection_timeout_sec,
    time_t connection_timeout_usec, time_t read_timeout_sec,
    time_t read_timeout_usec, time_t write_timeout_sec,
    time_t write_timeout_usec, const std::string &intf, Error &error) {
  auto sock = create_socket(
      host, ip, port, address_family, 0, tcp_nodelay, ipv6_v6only,
      std::move(socket_options),
      [&](socket_t sock2, struct addrinfo &ai, bool &quit) -> bool {
        if (!intf.empty()) {
#ifdef USE_IF2IP
          auto ip_from_if = if2ip(address_family, intf);
          if (ip_from_if.empty()) { ip_from_if = intf; }
          if (!bind_ip_address(sock2, ip_from_if)) {
            error = Error::BindIPAddress;
            return false;
          }
#endif
        }

        set_nonblocking(sock2, true);

        auto ret =
            ::connect(sock2, ai.ai_addr, static_cast<socklen_t>(ai.ai_addrlen));

        if (ret < 0) {
          if (is_connection_error()) {
            error = Error::Connection;
            return false;
          }
          error = wait_until_socket_is_ready(sock2, connection_timeout_sec,
                                             connection_timeout_usec);
          if (error != Error::Success) {
            if (error == Error::ConnectionTimeout) { quit = true; }
            return false;
          }
        }

        set_nonblocking(sock2, false);
        set_socket_opt_time(sock2, SOL_SOCKET, SO_RCVTIMEO, read_timeout_sec,
                            read_timeout_usec);
        set_socket_opt_time(sock2, SOL_SOCKET, SO_SNDTIMEO, write_timeout_sec,
                            write_timeout_usec);

        error = Error::Success;
        return true;
      },
      connection_timeout_sec); // Pass DNS timeout

  if (sock != INVALID_SOCKET) {
    error = Error::Success;
  } else {
    if (error == Error::Success) { error = Error::Connection; }
  }

  return sock;
}

inline bool get_ip_and_port(const struct sockaddr_storage &addr,
                            socklen_t addr_len, std::string &ip, int &port) {
  if (addr.ss_family == AF_INET) {
    port = ntohs(reinterpret_cast<const struct sockaddr_in *>(&addr)->sin_port);
  } else if (addr.ss_family == AF_INET6) {
    port =
        ntohs(reinterpret_cast<const struct sockaddr_in6 *>(&addr)->sin6_port);
  } else {
    return false;
  }

  std::array<char, NI_MAXHOST> ipstr{};
  if (getnameinfo(reinterpret_cast<const struct sockaddr *>(&addr), addr_len,
                  ipstr.data(), static_cast<socklen_t>(ipstr.size()), nullptr,
                  0, NI_NUMERICHOST)) {
    return false;
  }

  ip = ipstr.data();
  return true;
}

inline void get_local_ip_and_port(socket_t sock, std::string &ip, int &port) {
  struct sockaddr_storage addr;
  socklen_t addr_len = sizeof(addr);
  if (!getsockname(sock, reinterpret_cast<struct sockaddr *>(&addr),
                   &addr_len)) {
    get_ip_and_port(addr, addr_len, ip, port);
  }
}

inline void get_remote_ip_and_port(socket_t sock, std::string &ip, int &port) {
  struct sockaddr_storage addr;
  socklen_t addr_len = sizeof(addr);

  if (!getpeername(sock, reinterpret_cast<struct sockaddr *>(&addr),
                   &addr_len)) {
#ifndef _WIN64
    if (addr.ss_family == AF_UNIX) {
#if defined(__linux__)
      struct ucred ucred;
      socklen_t len = sizeof(ucred);
      if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &ucred, &len) == 0) {
        port = ucred.pid;
      }
#elif defined(SOL_LOCAL) && defined(SO_PEERPID)
      pid_t pid;
      socklen_t len = sizeof(pid);
      if (getsockopt(sock, SOL_LOCAL, SO_PEERPID, &pid, &len) == 0) {
        port = pid;
      }
#endif
      return;
    }
#endif
    get_ip_and_port(addr, addr_len, ip, port);
  }
}

inline constexpr unsigned int str2tag_core(const char *s, size_t l,
                                           unsigned int h) {
  return (l == 0)
             ? h
             : str2tag_core(
                   s + 1, l - 1,
                   // Unsets the 6 high bits of h, therefore no overflow happens
                   (((std::numeric_limits<unsigned int>::max)() >> 6) &
                    h * 33) ^
                       static_cast<unsigned char>(*s));
}

inline unsigned int str2tag(const std::string &s) {
  return str2tag_core(s.data(), s.size(), 0);
}

namespace udl {

inline constexpr unsigned int operator""_t(const char *s, size_t l) {
  return str2tag_core(s, l, 0);
}

} // namespace udl

inline std::string
find_content_type(const std::string &path,
                  const std::map<std::string, std::string> &user_data,
                  const std::string &default_content_type) {
  auto ext = file_extension(path);

  auto it = user_data.find(ext);
  if (it != user_data.end()) { return it->second; }

  using udl::operator""_t;

  switch (str2tag(ext)) {
  default: return default_content_type;

  case "css"_t: return "text/css";
  case "csv"_t: return "text/csv";
  case "htm"_t:
  case "html"_t: return "text/html";
  case "js"_t:
  case "mjs"_t: return "text/javascript";
  case "txt"_t: return "text/plain";
  case "vtt"_t: return "text/vtt";

  case "apng"_t: return "image/apng";
  case "avif"_t: return "image/avif";
  case "bmp"_t: return "image/bmp";
  case "gif"_t: return "image/gif";
  case "png"_t: return "image/png";
  case "svg"_t: return "image/svg+xml";
  case "webp"_t: return "image/webp";
  case "ico"_t: return "image/x-icon";
  case "tif"_t: return "image/tiff";
  case "tiff"_t: return "image/tiff";
  case "jpg"_t:
  case "jpeg"_t: return "image/jpeg";

  case "mp4"_t: return "video/mp4";
  case "mpeg"_t: return "video/mpeg";
  case "webm"_t: return "video/webm";

  case "mp3"_t: return "audio/mp3";
  case "mpga"_t: return "audio/mpeg";
  case "weba"_t: return "audio/webm";
  case "wav"_t: return "audio/wave";

  case "otf"_t: return "font/otf";
  case "ttf"_t: return "font/ttf";
  case "woff"_t: return "font/woff";
  case "woff2"_t: return "font/woff2";

  case "7z"_t: return "application/x-7z-compressed";
  case "atom"_t: return "application/atom+xml";
  case "pdf"_t: return "application/pdf";
  case "json"_t: return "application/json";
  case "rss"_t: return "application/rss+xml";
  case "tar"_t: return "application/x-tar";
  case "xht"_t:
  case "xhtml"_t: return "application/xhtml+xml";
  case "xslt"_t: return "application/xslt+xml";
  case "xml"_t: return "application/xml";
  case "gz"_t: return "application/gzip";
  case "zip"_t: return "application/zip";
  case "wasm"_t: return "application/wasm";
  }
}

inline bool can_compress_content_type(const std::string &content_type) {
  using udl::operator""_t;

  auto tag = str2tag(content_type);

  switch (tag) {
  case "image/svg+xml"_t:
  case "application/javascript"_t:
  case "application/json"_t:
  case "application/xml"_t:
  case "application/protobuf"_t:
  case "application/xhtml+xml"_t: return true;

  case "text/event-stream"_t: return false;

  default: return !content_type.rfind("text/", 0);
  }
}

inline EncodingType encoding_type(const Request &req, const Response &res) {
  auto ret =
      detail::can_compress_content_type(res.get_header_value("Content-Type"));
  if (!ret) { return EncodingType::None; }

  const auto &s = req.get_header_value("Accept-Encoding");
  (void)(s);

#ifdef CPPHTTPLIB_BROTLI_SUPPORT
  // TODO: 'Accept-Encoding' has br, not br;q=0
  ret = s.find("br") != std::string::npos;
  if (ret) { return EncodingType::Brotli; }
#endif

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
  // TODO: 'Accept-Encoding' has gzip, not gzip;q=0
  ret = s.find("gzip") != std::string::npos;
  if (ret) { return EncodingType::Gzip; }
#endif

#ifdef CPPHTTPLIB_ZSTD_SUPPORT
  // TODO: 'Accept-Encoding' has zstd, not zstd;q=0
  ret = s.find("zstd") != std::string::npos;
  if (ret) { return EncodingType::Zstd; }
#endif

  return EncodingType::None;
}

inline bool nocompressor::compress(const char *data, size_t data_length,
                                   bool /*last*/, Callback callback) {
  if (!data_length) { return true; }
  return callback(data, data_length);
}

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
inline gzip_compressor::gzip_compressor() {
  std::memset(&strm_, 0, sizeof(strm_));
  strm_.zalloc = Z_NULL;
  strm_.zfree = Z_NULL;
  strm_.opaque = Z_NULL;

  is_valid_ = deflateInit2(&strm_, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 31, 8,
                           Z_DEFAULT_STRATEGY) == Z_OK;
}

inline gzip_compressor::~gzip_compressor() { deflateEnd(&strm_); }

inline bool gzip_compressor::compress(const char *data, size_t data_length,
                                      bool last, Callback callback) {
  assert(is_valid_);

  do {
    constexpr size_t max_avail_in =
        (std::numeric_limits<decltype(strm_.avail_in)>::max)();

    strm_.avail_in = static_cast<decltype(strm_.avail_in)>(
        (std::min)(data_length, max_avail_in));
    strm_.next_in = const_cast<Bytef *>(reinterpret_cast<const Bytef *>(data));

    data_length -= strm_.avail_in;
    data += strm_.avail_in;

    auto flush = (last && data_length == 0) ? Z_FINISH : Z_NO_FLUSH;
    auto ret = Z_OK;

    std::array<char, CPPHTTPLIB_COMPRESSION_BUFSIZ> buff{};
    do {
      strm_.avail_out = static_cast<uInt>(buff.size());
      strm_.next_out = reinterpret_cast<Bytef *>(buff.data());

      ret = deflate(&strm_, flush);
      if (ret == Z_STREAM_ERROR) { return false; }

      if (!callback(buff.data(), buff.size() - strm_.avail_out)) {
        return false;
      }
    } while (strm_.avail_out == 0);

    assert((flush == Z_FINISH && ret == Z_STREAM_END) ||
           (flush == Z_NO_FLUSH && ret == Z_OK));
    assert(strm_.avail_in == 0);
  } while (data_length > 0);

  return true;
}

inline gzip_decompressor::gzip_decompressor() {
  std::memset(&strm_, 0, sizeof(strm_));
  strm_.zalloc = Z_NULL;
  strm_.zfree = Z_NULL;
  strm_.opaque = Z_NULL;

  // 15 is the value of wbits, which should be at the maximum possible value
  // to ensure that any gzip stream can be decoded. The offset of 32 specifies
  // that the stream type should be automatically detected either gzip or
  // deflate.
  is_valid_ = inflateInit2(&strm_, 32 + 15) == Z_OK;
}

inline gzip_decompressor::~gzip_decompressor() { inflateEnd(&strm_); }

inline bool gzip_decompressor::is_valid() const { return is_valid_; }

inline bool gzip_decompressor::decompress(const char *data, size_t data_length,
                                          Callback callback) {
  assert(is_valid_);

  auto ret = Z_OK;

  do {
    constexpr size_t max_avail_in =
        (std::numeric_limits<decltype(strm_.avail_in)>::max)();

    strm_.avail_in = static_cast<decltype(strm_.avail_in)>(
        (std::min)(data_length, max_avail_in));
    strm_.next_in = const_cast<Bytef *>(reinterpret_cast<const Bytef *>(data));

    data_length -= strm_.avail_in;
    data += strm_.avail_in;

    std::array<char, CPPHTTPLIB_COMPRESSION_BUFSIZ> buff{};
    while (strm_.avail_in > 0 && ret == Z_OK) {
      strm_.avail_out = static_cast<uInt>(buff.size());
      strm_.next_out = reinterpret_cast<Bytef *>(buff.data());

      ret = inflate(&strm_, Z_NO_FLUSH);

      assert(ret != Z_STREAM_ERROR);
      switch (ret) {
      case Z_NEED_DICT:
      case Z_DATA_ERROR:
      case Z_MEM_ERROR: inflateEnd(&strm_); return false;
      }

      if (!callback(buff.data(), buff.size() - strm_.avail_out)) {
        return false;
      }
    }

    if (ret != Z_OK && ret != Z_STREAM_END) { return false; }

  } while (data_length > 0);

  return true;
}
#endif

#ifdef CPPHTTPLIB_BROTLI_SUPPORT
inline brotli_compressor::brotli_compressor() {
  state_ = BrotliEncoderCreateInstance(nullptr, nullptr, nullptr);
}

inline brotli_compressor::~brotli_compressor() {
  BrotliEncoderDestroyInstance(state_);
}

inline bool brotli_compressor::compress(const char *data, size_t data_length,
                                        bool last, Callback callback) {
  std::array<uint8_t, CPPHTTPLIB_COMPRESSION_BUFSIZ> buff{};

  auto operation = last ? BROTLI_OPERATION_FINISH : BROTLI_OPERATION_PROCESS;
  auto available_in = data_length;
  auto next_in = reinterpret_cast<const uint8_t *>(data);

  for (;;) {
    if (last) {
      if (BrotliEncoderIsFinished(state_)) { break; }
    } else {
      if (!available_in) { break; }
    }

    auto available_out = buff.size();
    auto next_out = buff.data();

    if (!BrotliEncoderCompressStream(state_, operation, &available_in, &next_in,
                                     &available_out, &next_out, nullptr)) {
      return false;
    }

    auto output_bytes = buff.size() - available_out;
    if (output_bytes) {
      callback(reinterpret_cast<const char *>(buff.data()), output_bytes);
    }
  }

  return true;
}

inline brotli_decompressor::brotli_decompressor() {
  decoder_s = BrotliDecoderCreateInstance(0, 0, 0);
  decoder_r = decoder_s ? BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT
                        : BROTLI_DECODER_RESULT_ERROR;
}

inline brotli_decompressor::~brotli_decompressor() {
  if (decoder_s) { BrotliDecoderDestroyInstance(decoder_s); }
}

inline bool brotli_decompressor::is_valid() const { return decoder_s; }

inline bool brotli_decompressor::decompress(const char *data,
                                            size_t data_length,
                                            Callback callback) {
  if (decoder_r == BROTLI_DECODER_RESULT_SUCCESS ||
      decoder_r == BROTLI_DECODER_RESULT_ERROR) {
    return 0;
  }

  auto next_in = reinterpret_cast<const uint8_t *>(data);
  size_t avail_in = data_length;
  size_t total_out;

  decoder_r = BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT;

  std::array<char, CPPHTTPLIB_COMPRESSION_BUFSIZ> buff{};
  while (decoder_r == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {
    char *next_out = buff.data();
    size_t avail_out = buff.size();

    decoder_r = BrotliDecoderDecompressStream(
        decoder_s, &avail_in, &next_in, &avail_out,
        reinterpret_cast<uint8_t **>(&next_out), &total_out);

    if (decoder_r == BROTLI_DECODER_RESULT_ERROR) { return false; }

    if (!callback(buff.data(), buff.size() - avail_out)) { return false; }
  }

  return decoder_r == BROTLI_DECODER_RESULT_SUCCESS ||
         decoder_r == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT;
}
#endif

#ifdef CPPHTTPLIB_ZSTD_SUPPORT
inline zstd_compressor::zstd_compressor() {
  ctx_ = ZSTD_createCCtx();
  ZSTD_CCtx_setParameter(ctx_, ZSTD_c_compressionLevel, ZSTD_fast);
}

inline zstd_compressor::~zstd_compressor() { ZSTD_freeCCtx(ctx_); }

inline bool zstd_compressor::compress(const char *data, size_t data_length,
                                      bool last, Callback callback) {
  std::array<char, CPPHTTPLIB_COMPRESSION_BUFSIZ> buff{};

  ZSTD_EndDirective mode = last ? ZSTD_e_end : ZSTD_e_continue;
  ZSTD_inBuffer input = {data, data_length, 0};

  bool finished;
  do {
    ZSTD_outBuffer output = {buff.data(), CPPHTTPLIB_COMPRESSION_BUFSIZ, 0};
    size_t const remaining = ZSTD_compressStream2(ctx_, &output, &input, mode);

    if (ZSTD_isError(remaining)) { return false; }

    if (!callback(buff.data(), output.pos)) { return false; }

    finished = last ? (remaining == 0) : (input.pos == input.size);

  } while (!finished);

  return true;
}

inline zstd_decompressor::zstd_decompressor() { ctx_ = ZSTD_createDCtx(); }

inline zstd_decompressor::~zstd_decompressor() { ZSTD_freeDCtx(ctx_); }

inline bool zstd_decompressor::is_valid() const { return ctx_ != nullptr; }

inline bool zstd_decompressor::decompress(const char *data, size_t data_length,
                                          Callback callback) {
  std::array<char, CPPHTTPLIB_COMPRESSION_BUFSIZ> buff{};
  ZSTD_inBuffer input = {data, data_length, 0};

  while (input.pos < input.size) {
    ZSTD_outBuffer output = {buff.data(), CPPHTTPLIB_COMPRESSION_BUFSIZ, 0};
    size_t const remaining = ZSTD_decompressStream(ctx_, &output, &input);

    if (ZSTD_isError(remaining)) { return false; }

    if (!callback(buff.data(), output.pos)) { return false; }
  }

  return true;
}
#endif

inline bool has_header(const Headers &headers, const std::string &key) {
  return headers.find(key) != headers.end();
}

inline const char *get_header_value(const Headers &headers,
                                    const std::string &key, const char *def,
                                    size_t id) {
  auto rng = headers.equal_range(key);
  auto it = rng.first;
  std::advance(it, static_cast<ssize_t>(id));
  if (it != rng.second) { return it->second.c_str(); }
  return def;
}

template <typename T>
inline bool parse_header(const char *beg, const char *end, T fn) {
  // Skip trailing spaces and tabs.
  while (beg < end && is_space_or_tab(end[-1])) {
    end--;
  }

  auto p = beg;
  while (p < end && *p != ':') {
    p++;
  }

  auto name = std::string(beg, p);
  if (!detail::fields::is_field_name(name)) { return false; }

  if (p == end) { return false; }

  auto key_end = p;

  if (*p++ != ':') { return false; }

  while (p < end && is_space_or_tab(*p)) {
    p++;
  }

  if (p <= end) {
    auto key_len = key_end - beg;
    if (!key_len) { return false; }

    auto key = std::string(beg, key_end);
    auto val = std::string(p, end);

    if (!detail::fields::is_field_value(val)) { return false; }

    if (case_ignore::equal(key, "Location") ||
        case_ignore::equal(key, "Referer")) {
      fn(key, val);
    } else {
      fn(key, decode_path(val, false));
    }

    return true;
  }

  return false;
}

inline bool read_headers(Stream &strm, Headers &headers) {
  const auto bufsiz = 2048;
  char buf[bufsiz];
  stream_line_reader line_reader(strm, buf, bufsiz);

  size_t header_count = 0;

  for (;;) {
    if (!line_reader.getline()) { return false; }

    // Check if the line ends with CRLF.
    auto line_terminator_len = 2;
    if (line_reader.end_with_crlf()) {
      // Blank line indicates end of headers.
      if (line_reader.size() == 2) { break; }
    } else {
#ifdef CPPHTTPLIB_ALLOW_LF_AS_LINE_TERMINATOR
      // Blank line indicates end of headers.
      if (line_reader.size() == 1) { break; }
      line_terminator_len = 1;
#else
      continue; // Skip invalid line.
#endif
    }

    if (line_reader.size() > CPPHTTPLIB_HEADER_MAX_LENGTH) { return false; }

    // Check header count limit
    if (header_count >= CPPHTTPLIB_HEADER_MAX_COUNT) { return false; }

    // Exclude line terminator
    auto end = line_reader.ptr() + line_reader.size() - line_terminator_len;

    if (!parse_header(line_reader.ptr(), end,
                      [&](const std::string &key, const std::string &val) {
                        headers.emplace(key, val);
                      })) {
      return false;
    }

    header_count++;
  }

  return true;
}

inline bool read_content_with_length(Stream &strm, size_t len,
                                     DownloadProgress progress,
                                     ContentReceiverWithProgress out) {
  char buf[CPPHTTPLIB_RECV_BUFSIZ];

  size_t r = 0;
  while (r < len) {
    auto read_len = static_cast<size_t>(len - r);
    auto n = strm.read(buf, (std::min)(read_len, CPPHTTPLIB_RECV_BUFSIZ));
    if (n <= 0) { return false; }

    if (!out(buf, static_cast<size_t>(n), r, len)) { return false; }
    r += static_cast<size_t>(n);

    if (progress) {
      if (!progress(r, len)) { return false; }
    }
  }

  return true;
}

inline void skip_content_with_length(Stream &strm, size_t len) {
  char buf[CPPHTTPLIB_RECV_BUFSIZ];
  size_t r = 0;
  while (r < len) {
    auto read_len = static_cast<size_t>(len - r);
    auto n = strm.read(buf, (std::min)(read_len, CPPHTTPLIB_RECV_BUFSIZ));
    if (n <= 0) { return; }
    r += static_cast<size_t>(n);
  }
}

enum class ReadContentResult {
  Success,         // Successfully read the content
  PayloadTooLarge, // The content exceeds the specified payload limit
  Error            // An error occurred while reading the content
};

inline ReadContentResult
read_content_without_length(Stream &strm, size_t payload_max_length,
                            ContentReceiverWithProgress out) {
  char buf[CPPHTTPLIB_RECV_BUFSIZ];
  size_t r = 0;
  for (;;) {
    auto n = strm.read(buf, CPPHTTPLIB_RECV_BUFSIZ);
    if (n == 0) { return ReadContentResult::Success; }
    if (n < 0) { return ReadContentResult::Error; }

    // Check if adding this data would exceed the payload limit
    if (r > payload_max_length ||
        payload_max_length - r < static_cast<size_t>(n)) {
      return ReadContentResult::PayloadTooLarge;
    }

    if (!out(buf, static_cast<size_t>(n), r, 0)) {
      return ReadContentResult::Error;
    }
    r += static_cast<size_t>(n);
  }

  return ReadContentResult::Success;
}

template <typename T>
inline ReadContentResult read_content_chunked(Stream &strm, T &x,
                                              size_t payload_max_length,
                                              ContentReceiverWithProgress out) {
  const auto bufsiz = 16;
  char buf[bufsiz];

  stream_line_reader line_reader(strm, buf, bufsiz);

  if (!line_reader.getline()) { return ReadContentResult::Error; }

  unsigned long chunk_len;
  size_t total_len = 0;
  while (true) {
    char *end_ptr;

    chunk_len = std::strtoul(line_reader.ptr(), &end_ptr, 16);

    if (end_ptr == line_reader.ptr()) { return ReadContentResult::Error; }
    if (chunk_len == ULONG_MAX) { return ReadContentResult::Error; }

    if (chunk_len == 0) { break; }

    // Check if adding this chunk would exceed the payload limit
    if (total_len > payload_max_length ||
        payload_max_length - total_len < chunk_len) {
      return ReadContentResult::PayloadTooLarge;
    }

    total_len += chunk_len;

    if (!read_content_with_length(strm, chunk_len, nullptr, out)) {
      return ReadContentResult::Error;
    }

    if (!line_reader.getline()) { return ReadContentResult::Error; }

    if (strcmp(line_reader.ptr(), "\r\n") != 0) {
      return ReadContentResult::Error;
    }

    if (!line_reader.getline()) { return ReadContentResult::Error; }
  }

  assert(chunk_len == 0);

  // NOTE: In RFC 9112, '7.1 Chunked Transfer Coding' mentions "The chunked
  // transfer coding is complete when a chunk with a chunk-size of zero is
  // received, possibly followed by a trailer section, and finally terminated by
  // an empty line". https://www.rfc-editor.org/rfc/rfc9112.html#section-7.1
  //
  // In '7.1.3. Decoding Chunked', however, the pseudo-code in the section
  // does't care for the existence of the final CRLF. In other words, it seems
  // to be ok whether the final CRLF exists or not in the chunked data.
  // https://www.rfc-editor.org/rfc/rfc9112.html#section-7.1.3
  //
  // According to the reference code in RFC 9112, cpp-httplib now allows
  // chunked transfer coding data without the final CRLF.
  if (!line_reader.getline()) { return ReadContentResult::Success; }

  // RFC 7230 Section 4.1.2 - Headers prohibited in trailers
  thread_local case_ignore::unordered_set<std::string> prohibited_trailers = {
      // Message framing
      "transfer-encoding", "content-length",

      // Routing
      "host",

      // Authentication
      "authorization", "www-authenticate", "proxy-authenticate",
      "proxy-authorization", "cookie", "set-cookie",

      // Request modifiers
      "cache-control", "expect", "max-forwards", "pragma", "range", "te",

      // Response control
      "age", "expires", "date", "location", "retry-after", "vary", "warning",

      // Payload processing
      "content-encoding", "content-type", "content-range", "trailer"};

  // Parse declared trailer headers once for performance
  case_ignore::unordered_set<std::string> declared_trailers;
  if (has_header(x.headers, "Trailer")) {
    auto trailer_header = get_header_value(x.headers, "Trailer", "", 0);
    auto len = std::strlen(trailer_header);

    split(trailer_header, trailer_header + len, ',',
          [&](const char *b, const char *e) {
            std::string key(b, e);
            if (prohibited_trailers.find(key) == prohibited_trailers.end()) {
              declared_trailers.insert(key);
            }
          });
  }

  size_t trailer_header_count = 0;
  while (strcmp(line_reader.ptr(), "\r\n") != 0) {
    if (line_reader.size() > CPPHTTPLIB_HEADER_MAX_LENGTH) {
      return ReadContentResult::Error;
    }

    // Check trailer header count limit
    if (trailer_header_count >= CPPHTTPLIB_HEADER_MAX_COUNT) {
      return ReadContentResult::Error;
    }

    // Exclude line terminator
    constexpr auto line_terminator_len = 2;
    auto end = line_reader.ptr() + line_reader.size() - line_terminator_len;

    parse_header(line_reader.ptr(), end,
                 [&](const std::string &key, const std::string &val) {
                   if (declared_trailers.find(key) != declared_trailers.end()) {
                     x.trailers.emplace(key, val);
                     trailer_header_count++;
                   }
                 });

    if (!line_reader.getline()) { return ReadContentResult::Error; }
  }

  return ReadContentResult::Success;
}

inline bool is_chunked_transfer_encoding(const Headers &headers) {
  return case_ignore::equal(
      get_header_value(headers, "Transfer-Encoding", "", 0), "chunked");
}

template <typename T, typename U>
bool prepare_content_receiver(T &x, int &status,
                              ContentReceiverWithProgress receiver,
                              bool decompress, U callback) {
  if (decompress) {
    std::string encoding = x.get_header_value("Content-Encoding");
    std::unique_ptr<decompressor> decompressor;

    if (encoding == "gzip" || encoding == "deflate") {
#ifdef CPPHTTPLIB_ZLIB_SUPPORT
      decompressor = detail::make_unique<gzip_decompressor>();
#else
      status = StatusCode::UnsupportedMediaType_415;
      return false;
#endif
    } else if (encoding.find("br") != std::string::npos) {
#ifdef CPPHTTPLIB_BROTLI_SUPPORT
      decompressor = detail::make_unique<brotli_decompressor>();
#else
      status = StatusCode::UnsupportedMediaType_415;
      return false;
#endif
    } else if (encoding == "zstd") {
#ifdef CPPHTTPLIB_ZSTD_SUPPORT
      decompressor = detail::make_unique<zstd_decompressor>();
#else
      status = StatusCode::UnsupportedMediaType_415;
      return false;
#endif
    }

    if (decompressor) {
      if (decompressor->is_valid()) {
        ContentReceiverWithProgress out = [&](const char *buf, size_t n,
                                              size_t off, size_t len) {
          return decompressor->decompress(buf, n,
                                          [&](const char *buf2, size_t n2) {
                                            return receiver(buf2, n2, off, len);
                                          });
        };
        return callback(std::move(out));
      } else {
        status = StatusCode::InternalServerError_500;
        return false;
      }
    }
  }

  ContentReceiverWithProgress out = [&](const char *buf, size_t n, size_t off,
                                        size_t len) {
    return receiver(buf, n, off, len);
  };
  return callback(std::move(out));
}

template <typename T>
bool read_content(Stream &strm, T &x, size_t payload_max_length, int &status,
                  DownloadProgress progress,
                  ContentReceiverWithProgress receiver, bool decompress) {
  return prepare_content_receiver(
      x, status, std::move(receiver), decompress,
      [&](const ContentReceiverWithProgress &out) {
        auto ret = true;
        auto exceed_payload_max_length = false;

        if (is_chunked_transfer_encoding(x.headers)) {
          auto result = read_content_chunked(strm, x, payload_max_length, out);
          if (result == ReadContentResult::Success) {
            ret = true;
          } else if (result == ReadContentResult::PayloadTooLarge) {
            exceed_payload_max_length = true;
            ret = false;
          } else {
            ret = false;
          }
        } else if (!has_header(x.headers, "Content-Length")) {
          auto result =
              read_content_without_length(strm, payload_max_length, out);
          if (result == ReadContentResult::Success) {
            ret = true;
          } else if (result == ReadContentResult::PayloadTooLarge) {
            exceed_payload_max_length = true;
            ret = false;
          } else {
            ret = false;
          }
        } else {
          auto is_invalid_value = false;
          auto len = get_header_value_u64(x.headers, "Content-Length",
                                          (std::numeric_limits<size_t>::max)(),
                                          0, is_invalid_value);

          if (is_invalid_value) {
            ret = false;
          } else if (len > payload_max_length) {
            exceed_payload_max_length = true;
            skip_content_with_length(strm, len);
            ret = false;
          } else if (len > 0) {
            ret = read_content_with_length(strm, len, std::move(progress), out);
          }
        }

        if (!ret) {
          status = exceed_payload_max_length ? StatusCode::PayloadTooLarge_413
                                             : StatusCode::BadRequest_400;
        }
        return ret;
      });
}

inline ssize_t write_request_line(Stream &strm, const std::string &method,
                                  const std::string &path) {
  std::string s = method;
  s += " ";
  s += path;
  s += " HTTP/1.1\r\n";
  return strm.write(s.data(), s.size());
}

inline ssize_t write_response_line(Stream &strm, int status) {
  std::string s = "HTTP/1.1 ";
  s += std::to_string(status);
  s += " ";
  s += httplib::status_message(status);
  s += "\r\n";
  return strm.write(s.data(), s.size());
}

inline ssize_t write_headers(Stream &strm, const Headers &headers) {
  ssize_t write_len = 0;
  for (const auto &x : headers) {
    std::string s;
    s = x.first;
    s += ": ";
    s += x.second;
    s += "\r\n";

    auto len = strm.write(s.data(), s.size());
    if (len < 0) { return len; }
    write_len += len;
  }
  auto len = strm.write("\r\n");
  if (len < 0) { return len; }
  write_len += len;
  return write_len;
}

inline bool write_data(Stream &strm, const char *d, size_t l) {
  size_t offset = 0;
  while (offset < l) {
    auto length = strm.write(d + offset, l - offset);
    if (length < 0) { return false; }
    offset += static_cast<size_t>(length);
  }
  return true;
}

template <typename T>
inline bool write_content_with_progress(Stream &strm,
                                        const ContentProvider &content_provider,
                                        size_t offset, size_t length,
                                        T is_shutting_down,
                                        const UploadProgress &upload_progress,
                                        Error &error) {
  size_t end_offset = offset + length;
  size_t start_offset = offset;
  auto ok = true;
  DataSink data_sink;

  data_sink.write = [&](const char *d, size_t l) -> bool {
    if (ok) {
      if (write_data(strm, d, l)) {
        offset += l;

        if (upload_progress && length > 0) {
          size_t current_written = offset - start_offset;
          if (!upload_progress(current_written, length)) {
            ok = false;
            return false;
          }
        }
      } else {
        ok = false;
      }
    }
    return ok;
  };

  data_sink.is_writable = [&]() -> bool { return strm.wait_writable(); };

  while (offset < end_offset && !is_shutting_down()) {
    if (!strm.wait_writable()) {
      error = Error::Write;
      return false;
    } else if (!content_provider(offset, end_offset - offset, data_sink)) {
      error = Error::Canceled;
      return false;
    } else if (!ok) {
      error = Error::Write;
      return false;
    }
  }

  error = Error::Success;
  return true;
}

template <typename T>
inline bool write_content(Stream &strm, const ContentProvider &content_provider,
                          size_t offset, size_t length, T is_shutting_down,
                          Error &error) {
  return write_content_with_progress<T>(strm, content_provider, offset, length,
                                        is_shutting_down, nullptr, error);
}

template <typename T>
inline bool write_content(Stream &strm, const ContentProvider &content_provider,
                          size_t offset, size_t length,
                          const T &is_shutting_down) {
  auto error = Error::Success;
  return write_content(strm, content_provider, offset, length, is_shutting_down,
                       error);
}

template <typename T>
inline bool
write_content_without_length(Stream &strm,
                             const ContentProvider &content_provider,
                             const T &is_shutting_down) {
  size_t offset = 0;
  auto data_available = true;
  auto ok = true;
  DataSink data_sink;

  data_sink.write = [&](const char *d, size_t l) -> bool {
    if (ok) {
      offset += l;
      if (!write_data(strm, d, l)) { ok = false; }
    }
    return ok;
  };

  data_sink.is_writable = [&]() -> bool { return strm.wait_writable(); };

  data_sink.done = [&](void) { data_available = false; };

  while (data_available && !is_shutting_down()) {
    if (!strm.wait_writable()) {
      return false;
    } else if (!content_provider(offset, 0, data_sink)) {
      return false;
    } else if (!ok) {
      return false;
    }
  }
  return true;
}

template <typename T, typename U>
inline bool
write_content_chunked(Stream &strm, const ContentProvider &content_provider,
                      const T &is_shutting_down, U &compressor, Error &error) {
  size_t offset = 0;
  auto data_available = true;
  auto ok = true;
  DataSink data_sink;

  data_sink.write = [&](const char *d, size_t l) -> bool {
    if (ok) {
      data_available = l > 0;
      offset += l;

      std::string payload;
      if (compressor.compress(d, l, false,
                              [&](const char *data, size_t data_len) {
                                payload.append(data, data_len);
                                return true;
                              })) {
        if (!payload.empty()) {
          // Emit chunked response header and footer for each chunk
          auto chunk =
              from_i_to_hex(payload.size()) + "\r\n" + payload + "\r\n";
          if (!write_data(strm, chunk.data(), chunk.size())) { ok = false; }
        }
      } else {
        ok = false;
      }
    }
    return ok;
  };

  data_sink.is_writable = [&]() -> bool { return strm.wait_writable(); };

  auto done_with_trailer = [&](const Headers *trailer) {
    if (!ok) { return; }

    data_available = false;

    std::string payload;
    if (!compressor.compress(nullptr, 0, true,
                             [&](const char *data, size_t data_len) {
                               payload.append(data, data_len);
                               return true;
                             })) {
      ok = false;
      return;
    }

    if (!payload.empty()) {
      // Emit chunked response header and footer for each chunk
      auto chunk = from_i_to_hex(payload.size()) + "\r\n" + payload + "\r\n";
      if (!write_data(strm, chunk.data(), chunk.size())) {
        ok = false;
        return;
      }
    }

    constexpr const char done_marker[] = "0\r\n";
    if (!write_data(strm, done_marker, str_len(done_marker))) { ok = false; }

    // Trailer
    if (trailer) {
      for (const auto &kv : *trailer) {
        std::string field_line = kv.first + ": " + kv.second + "\r\n";
        if (!write_data(strm, field_line.data(), field_line.size())) {
          ok = false;
        }
      }
    }

    constexpr const char crlf[] = "\r\n";
    if (!write_data(strm, crlf, str_len(crlf))) { ok = false; }
  };

  data_sink.done = [&](void) { done_with_trailer(nullptr); };

  data_sink.done_with_trailer = [&](const Headers &trailer) {
    done_with_trailer(&trailer);
  };

  while (data_available && !is_shutting_down()) {
    if (!strm.wait_writable()) {
      error = Error::Write;
      return false;
    } else if (!content_provider(offset, 0, data_sink)) {
      error = Error::Canceled;
      return false;
    } else if (!ok) {
      error = Error::Write;
      return false;
    }
  }

  error = Error::Success;
  return true;
}

template <typename T, typename U>
inline bool write_content_chunked(Stream &strm,
                                  const ContentProvider &content_provider,
                                  const T &is_shutting_down, U &compressor) {
  auto error = Error::Success;
  return write_content_chunked(strm, content_provider, is_shutting_down,
                               compressor, error);
}

template <typename T>
inline bool redirect(T &cli, Request &req, Response &res,
                     const std::string &path, const std::string &location,
                     Error &error) {
  Request new_req = req;
  new_req.path = path;
  new_req.redirect_count_ -= 1;

  if (res.status == StatusCode::SeeOther_303 &&
      (req.method != "GET" && req.method != "HEAD")) {
    new_req.method = "GET";
    new_req.body.clear();
    new_req.headers.clear();
  }

  Response new_res;

  auto ret = cli.send(new_req, new_res, error);
  if (ret) {
    req = new_req;
    res = new_res;

    if (res.location.empty()) { res.location = location; }
  }
  return ret;
}

inline std::string params_to_query_str(const Params &params) {
  std::string query;

  for (auto it = params.begin(); it != params.end(); ++it) {
    if (it != params.begin()) { query += "&"; }
    query += it->first;
    query += "=";
    query += httplib::encode_uri_component(it->second);
  }
  return query;
}

inline void parse_query_text(const char *data, std::size_t size,
                             Params &params) {
  std::set<std::string> cache;
  split(data, data + size, '&', [&](const char *b, const char *e) {
    std::string kv(b, e);
    if (cache.find(kv) != cache.end()) { return; }
    cache.insert(std::move(kv));

    std::string key;
    std::string val;
    divide(b, static_cast<std::size_t>(e - b), '=',
           [&](const char *lhs_data, std::size_t lhs_size, const char *rhs_data,
               std::size_t rhs_size) {
             key.assign(lhs_data, lhs_size);
             val.assign(rhs_data, rhs_size);
           });

    if (!key.empty()) {
      params.emplace(decode_path(key, true), decode_path(val, true));
    }
  });
}

inline void parse_query_text(const std::string &s, Params &params) {
  parse_query_text(s.data(), s.size(), params);
}

inline bool parse_multipart_boundary(const std::string &content_type,
                                     std::string &boundary) {
  auto boundary_keyword = "boundary=";
  auto pos = content_type.find(boundary_keyword);
  if (pos == std::string::npos) { return false; }
  auto end = content_type.find(';', pos);
  auto beg = pos + strlen(boundary_keyword);
  boundary = trim_double_quotes_copy(content_type.substr(beg, end - beg));
  return !boundary.empty();
}

inline void parse_disposition_params(const std::string &s, Params &params) {
  std::set<std::string> cache;
  split(s.data(), s.data() + s.size(), ';', [&](const char *b, const char *e) {
    std::string kv(b, e);
    if (cache.find(kv) != cache.end()) { return; }
    cache.insert(kv);

    std::string key;
    std::string val;
    split(b, e, '=', [&](const char *b2, const char *e2) {
      if (key.empty()) {
        key.assign(b2, e2);
      } else {
        val.assign(b2, e2);
      }
    });

    if (!key.empty()) {
      params.emplace(trim_double_quotes_copy((key)),
                     trim_double_quotes_copy((val)));
    }
  });
}

#ifdef CPPHTTPLIB_NO_EXCEPTIONS
inline bool parse_range_header(const std::string &s, Ranges &ranges) {
#else
inline bool parse_range_header(const std::string &s, Ranges &ranges) try {
#endif
  auto is_valid = [](const std::string &str) {
    return std::all_of(str.cbegin(), str.cend(),
                       [](unsigned char c) { return std::isdigit(c); });
  };

  if (s.size() > 7 && s.compare(0, 6, "bytes=") == 0) {
    const auto pos = static_cast<size_t>(6);
    const auto len = static_cast<size_t>(s.size() - 6);
    auto all_valid_ranges = true;
    split(&s[pos], &s[pos + len], ',', [&](const char *b, const char *e) {
      if (!all_valid_ranges) { return; }

      const auto it = std::find(b, e, '-');
      if (it == e) {
        all_valid_ranges = false;
        return;
      }

      const auto lhs = std::string(b, it);
      const auto rhs = std::string(it + 1, e);
      if (!is_valid(lhs) || !is_valid(rhs)) {
        all_valid_ranges = false;
        return;
      }

      const auto first =
          static_cast<ssize_t>(lhs.empty() ? -1 : std::stoll(lhs));
      const auto last =
          static_cast<ssize_t>(rhs.empty() ? -1 : std::stoll(rhs));
      if ((first == -1 && last == -1) ||
          (first != -1 && last != -1 && first > last)) {
        all_valid_ranges = false;
        return;
      }

      ranges.emplace_back(first, last);
    });
    return all_valid_ranges && !ranges.empty();
  }
  return false;
#ifdef CPPHTTPLIB_NO_EXCEPTIONS
}
#else
} catch (...) { return false; }
#endif

inline bool parse_accept_header(const std::string &s,
                                std::vector<std::string> &content_types) {
  content_types.clear();

  // Empty string is considered valid (no preference)
  if (s.empty()) { return true; }

  // Check for invalid patterns: leading/trailing commas or consecutive commas
  if (s.front() == ',' || s.back() == ',' ||
      s.find(",,") != std::string::npos) {
    return false;
  }

  struct AcceptEntry {
    std::string media_type;
    double quality;
    int order; // Original order in header
  };

  std::vector<AcceptEntry> entries;
  int order = 0;
  bool has_invalid_entry = false;

  // Split by comma and parse each entry
  split(s.data(), s.data() + s.size(), ',', [&](const char *b, const char *e) {
    std::string entry(b, e);
    entry = trim_copy(entry);

    if (entry.empty()) {
      has_invalid_entry = true;
      return;
    }

    AcceptEntry accept_entry;
    accept_entry.quality = 1.0; // Default quality
    accept_entry.order = order++;

    // Find q= parameter
    auto q_pos = entry.find(";q=");
    if (q_pos == std::string::npos) { q_pos = entry.find("; q="); }

    if (q_pos != std::string::npos) {
      // Extract media type (before q parameter)
      accept_entry.media_type = trim_copy(entry.substr(0, q_pos));

      // Extract quality value
      auto q_start = entry.find('=', q_pos) + 1;
      auto q_end = entry.find(';', q_start);
      if (q_end == std::string::npos) { q_end = entry.length(); }

      std::string quality_str =
          trim_copy(entry.substr(q_start, q_end - q_start));
      if (quality_str.empty()) {
        has_invalid_entry = true;
        return;
      }

      try {
        accept_entry.quality = std::stod(quality_str);
        // Check if quality is in valid range [0.0, 1.0]
        if (accept_entry.quality < 0.0 || accept_entry.quality > 1.0) {
          has_invalid_entry = true;
          return;
        }
      } catch (...) {
        has_invalid_entry = true;
        return;
      }
    } else {
      // No quality parameter, use entire entry as media type
      accept_entry.media_type = entry;
    }

    // Remove additional parameters from media type
    auto param_pos = accept_entry.media_type.find(';');
    if (param_pos != std::string::npos) {
      accept_entry.media_type =
          trim_copy(accept_entry.media_type.substr(0, param_pos));
    }

    // Basic validation of media type
    if (accept_entry.media_type.empty()) {
      has_invalid_entry = true;
      return;
    }

    // Check for basic media type format (should contain '/' or be '*')
    if (accept_entry.media_type != "*" &&
        accept_entry.media_type.find('/') == std::string::npos) {
      has_invalid_entry = true;
      return;
    }

    entries.push_back(accept_entry);
  });

  // Return false if any invalid entry was found
  if (has_invalid_entry) { return false; }

  // Sort by quality (descending), then by original order (ascending)
  std::sort(entries.begin(), entries.end(),
            [](const AcceptEntry &a, const AcceptEntry &b) {
              if (a.quality != b.quality) {
                return a.quality > b.quality; // Higher quality first
              }
              return a.order < b.order; // Earlier order first for same quality
            });

  // Extract sorted media types
  content_types.reserve(entries.size());
  for (const auto &entry : entries) {
    content_types.push_back(entry.media_type);
  }

  return true;
}

class FormDataParser {
public:
  FormDataParser() = default;

  void set_boundary(std::string &&boundary) {
    boundary_ = boundary;
    dash_boundary_crlf_ = dash_ + boundary_ + crlf_;
    crlf_dash_boundary_ = crlf_ + dash_ + boundary_;
  }

  bool is_valid() const { return is_valid_; }

  bool parse(const char *buf, size_t n, const FormDataHeader &header_callback,
             const ContentReceiver &content_callback) {

    buf_append(buf, n);

    while (buf_size() > 0) {
      switch (state_) {
      case 0: { // Initial boundary
        auto pos = buf_find(dash_boundary_crlf_);
        if (pos == buf_size()) { return true; }
        buf_erase(pos + dash_boundary_crlf_.size());
        state_ = 1;
        break;
      }
      case 1: { // New entry
        clear_file_info();
        state_ = 2;
        break;
      }
      case 2: { // Headers
        auto pos = buf_find(crlf_);
        if (pos > CPPHTTPLIB_HEADER_MAX_LENGTH) { return false; }
        while (pos < buf_size()) {
          // Empty line
          if (pos == 0) {
            if (!header_callback(file_)) {
              is_valid_ = false;
              return false;
            }
            buf_erase(crlf_.size());
            state_ = 3;
            break;
          }

          const auto header = buf_head(pos);

          if (!parse_header(header.data(), header.data() + header.size(),
                            [&](const std::string &, const std::string &) {})) {
            is_valid_ = false;
            return false;
          }

          // Parse and emplace space trimmed headers into a map
          if (!parse_header(
                  header.data(), header.data() + header.size(),
                  [&](const std::string &key, const std::string &val) {
                    file_.headers.emplace(key, val);
                  })) {
            is_valid_ = false;
            return false;
          }

          constexpr const char header_content_type[] = "Content-Type:";

          if (start_with_case_ignore(header, header_content_type)) {
            file_.content_type =
                trim_copy(header.substr(str_len(header_content_type)));
          } else {
            thread_local const std::regex re_content_disposition(
                R"~(^Content-Disposition:\s*form-data;\s*(.*)$)~",
                std::regex_constants::icase);

            std::smatch m;
            if (std::regex_match(header, m, re_content_disposition)) {
              Params params;
              parse_disposition_params(m[1], params);

              auto it = params.find("name");
              if (it != params.end()) {
                file_.name = it->second;
              } else {
                is_valid_ = false;
                return false;
              }

              it = params.find("filename");
              if (it != params.end()) { file_.filename = it->second; }

              it = params.find("filename*");
              if (it != params.end()) {
                // Only allow UTF-8 encoding...
                thread_local const std::regex re_rfc5987_encoding(
                    R"~(^UTF-8''(.+?)$)~", std::regex_constants::icase);

                std::smatch m2;
                if (std::regex_match(it->second, m2, re_rfc5987_encoding)) {
                  file_.filename = decode_path(m2[1], false); // override...
                } else {
                  is_valid_ = false;
                  return false;
                }
              }
            }
          }
          buf_erase(pos + crlf_.size());
          pos = buf_find(crlf_);
        }
        if (state_ != 3) { return true; }
        break;
      }
      case 3: { // Body
        if (crlf_dash_boundary_.size() > buf_size()) { return true; }
        auto pos = buf_find(crlf_dash_boundary_);
        if (pos < buf_size()) {
          if (!content_callback(buf_data(), pos)) {
            is_valid_ = false;
            return false;
          }
          buf_erase(pos + crlf_dash_boundary_.size());
          state_ = 4;
        } else {
          auto len = buf_size() - crlf_dash_boundary_.size();
          if (len > 0) {
            if (!content_callback(buf_data(), len)) {
              is_valid_ = false;
              return false;
            }
            buf_erase(len);
          }
          return true;
        }
        break;
      }
      case 4: { // Boundary
        if (crlf_.size() > buf_size()) { return true; }
        if (buf_start_with(crlf_)) {
          buf_erase(crlf_.size());
          state_ = 1;
        } else {
          if (dash_.size() > buf_size()) { return true; }
          if (buf_start_with(dash_)) {
            buf_erase(dash_.size());
            is_valid_ = true;
            buf_erase(buf_size()); // Remove epilogue
          } else {
            return true;
          }
        }
        break;
      }
      }
    }

    return true;
  }

private:
  void clear_file_info() {
    file_.name.clear();
    file_.filename.clear();
    file_.content_type.clear();
    file_.headers.clear();
  }

  bool start_with_case_ignore(const std::string &a, const char *b) const {
    const auto b_len = strlen(b);
    if (a.size() < b_len) { return false; }
    for (size_t i = 0; i < b_len; i++) {
      if (case_ignore::to_lower(a[i]) != case_ignore::to_lower(b[i])) {
        return false;
      }
    }
    return true;
  }

  const std::string dash_ = "--";
  const std::string crlf_ = "\r\n";
  std::string boundary_;
  std::string dash_boundary_crlf_;
  std::string crlf_dash_boundary_;

  size_t state_ = 0;
  bool is_valid_ = false;
  FormData file_;

  // Buffer
  bool start_with(const std::string &a, size_t spos, size_t epos,
                  const std::string &b) const {
    if (epos - spos < b.size()) { return false; }
    for (size_t i = 0; i < b.size(); i++) {
      if (a[i + spos] != b[i]) { return false; }
    }
    return true;
  }

  size_t buf_size() const { return buf_epos_ - buf_spos_; }

  const char *buf_data() const { return &buf_[buf_spos_]; }

  std::string buf_head(size_t l) const { return buf_.substr(buf_spos_, l); }

  bool buf_start_with(const std::string &s) const {
    return start_with(buf_, buf_spos_, buf_epos_, s);
  }

  size_t buf_find(const std::string &s) const {
    auto c = s.front();

    size_t off = buf_spos_;
    while (off < buf_epos_) {
      auto pos = off;
      while (true) {
        if (pos == buf_epos_) { return buf_size(); }
        if (buf_[pos] == c) { break; }
        pos++;
      }

      auto remaining_size = buf_epos_ - pos;
      if (s.size() > remaining_size) { return buf_size(); }

      if (start_with(buf_, pos, buf_epos_, s)) { return pos - buf_spos_; }

      off = pos + 1;
    }

    return buf_size();
  }

  void buf_append(const char *data, size_t n) {
    auto remaining_size = buf_size();
    if (remaining_size > 0 && buf_spos_ > 0) {
      for (size_t i = 0; i < remaining_size; i++) {
        buf_[i] = buf_[buf_spos_ + i];
      }
    }
    buf_spos_ = 0;
    buf_epos_ = remaining_size;

    if (remaining_size + n > buf_.size()) { buf_.resize(remaining_size + n); }

    for (size_t i = 0; i < n; i++) {
      buf_[buf_epos_ + i] = data[i];
    }
    buf_epos_ += n;
  }

  void buf_erase(size_t size) { buf_spos_ += size; }

  std::string buf_;
  size_t buf_spos_ = 0;
  size_t buf_epos_ = 0;
};

inline std::string random_string(size_t length) {
  constexpr const char data[] =
      "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  thread_local auto engine([]() {
    // std::random_device might actually be deterministic on some
    // platforms, but due to lack of support in the c++ standard library,
    // doing better requires either some ugly hacks or breaking portability.
    std::random_device seed_gen;
    // Request 128 bits of entropy for initialization
    std::seed_seq seed_sequence{seed_gen(), seed_gen(), seed_gen(), seed_gen()};
    return std::mt19937(seed_sequence);
  }());

  std::string result;
  for (size_t i = 0; i < length; i++) {
    result += data[engine() % (sizeof(data) - 1)];
  }
  return result;
}

inline std::string make_multipart_data_boundary() {
  return "--cpp-httplib-multipart-data-" + detail::random_string(16);
}

inline bool is_multipart_boundary_chars_valid(const std::string &boundary) {
  auto valid = true;
  for (size_t i = 0; i < boundary.size(); i++) {
    auto c = boundary[i];
    if (!std::isalnum(c) && c != '-' && c != '_') {
      valid = false;
      break;
    }
  }
  return valid;
}

template <typename T>
inline std::string
serialize_multipart_formdata_item_begin(const T &item,
                                        const std::string &boundary) {
  std::string body = "--" + boundary + "\r\n";
  body += "Content-Disposition: form-data; name=\"" + item.name + "\"";
  if (!item.filename.empty()) {
    body += "; filename=\"" + item.filename + "\"";
  }
  body += "\r\n";
  if (!item.content_type.empty()) {
    body += "Content-Type: " + item.content_type + "\r\n";
  }
  body += "\r\n";

  return body;
}

inline std::string serialize_multipart_formdata_item_end() { return "\r\n"; }

inline std::string
serialize_multipart_formdata_finish(const std::string &boundary) {
  return "--" + boundary + "--\r\n";
}

inline std::string
serialize_multipart_formdata_get_content_type(const std::string &boundary) {
  return "multipart/form-data; boundary=" + boundary;
}

inline std::string
serialize_multipart_formdata(const UploadFormDataItems &items,
                             const std::string &boundary, bool finish = true) {
  std::string body;

  for (const auto &item : items) {
    body += serialize_multipart_formdata_item_begin(item, boundary);
    body += item.content + serialize_multipart_formdata_item_end();
  }

  if (finish) { body += serialize_multipart_formdata_finish(boundary); }

  return body;
}

inline void coalesce_ranges(Ranges &ranges, size_t content_length) {
  if (ranges.size() <= 1) return;

  // Sort ranges by start position
  std::sort(ranges.begin(), ranges.end(),
            [](const Range &a, const Range &b) { return a.first < b.first; });

  Ranges coalesced;
  coalesced.reserve(ranges.size());

  for (auto &r : ranges) {
    auto first_pos = r.first;
    auto last_pos = r.second;

    // Handle special cases like in range_error
    if (first_pos == -1 && last_pos == -1) {
      first_pos = 0;
      last_pos = static_cast<ssize_t>(content_length);
    }

    if (first_pos == -1) {
      first_pos = static_cast<ssize_t>(content_length) - last_pos;
      last_pos = static_cast<ssize_t>(content_length) - 1;
    }

    if (last_pos == -1 || last_pos >= static_cast<ssize_t>(content_length)) {
      last_pos = static_cast<ssize_t>(content_length) - 1;
    }

    // Skip invalid ranges
    if (!(0 <= first_pos && first_pos <= last_pos &&
          last_pos < static_cast<ssize_t>(content_length))) {
      continue;
    }

    // Coalesce with previous range if overlapping or adjacent (but not
    // identical)
    if (!coalesced.empty()) {
      auto &prev = coalesced.back();
      // Check if current range overlaps or is adjacent to previous range
      // but don't coalesce identical ranges (allow duplicates)
      if (first_pos <= prev.second + 1 &&
          !(first_pos == prev.first && last_pos == prev.second)) {
        // Extend the previous range
        prev.second = (std::max)(prev.second, last_pos);
        continue;
      }
    }

    // Add new range
    coalesced.emplace_back(first_pos, last_pos);
  }

  ranges = std::move(coalesced);
}

inline bool range_error(Request &req, Response &res) {
  if (!req.ranges.empty() && 200 <= res.status && res.status < 300) {
    ssize_t content_len = static_cast<ssize_t>(
        res.content_length_ ? res.content_length_ : res.body.size());

    std::vector<std::pair<ssize_t, ssize_t>> processed_ranges;
    size_t overwrapping_count = 0;

    // NOTE: The following Range check is based on '14.2. Range' in RFC 9110
    // 'HTTP Semantics' to avoid potential denial-of-service attacks.
    // https://www.rfc-editor.org/rfc/rfc9110#section-14.2

    // Too many ranges
    if (req.ranges.size() > CPPHTTPLIB_RANGE_MAX_COUNT) { return true; }

    for (auto &r : req.ranges) {
      auto &first_pos = r.first;
      auto &last_pos = r.second;

      if (first_pos == -1 && last_pos == -1) {
        first_pos = 0;
        last_pos = content_len;
      }

      if (first_pos == -1) {
        first_pos = content_len - last_pos;
        last_pos = content_len - 1;
      }

      // NOTE: RFC-9110 '14.1.2. Byte Ranges':
      // A client can limit the number of bytes requested without knowing the
      // size of the selected representation. If the last-pos value is absent,
      // or if the value is greater than or equal to the current length of the
      // representation data, the byte range is interpreted as the remainder of
      // the representation (i.e., the server replaces the value of last-pos
      // with a value that is one less than the current length of the selected
      // representation).
      // https://www.rfc-editor.org/rfc/rfc9110.html#section-14.1.2-6
      if (last_pos == -1 || last_pos >= content_len) {
        last_pos = content_len - 1;
      }

      // Range must be within content length
      if (!(0 <= first_pos && first_pos <= last_pos &&
            last_pos <= content_len - 1)) {
        return true;
      }

      // Request must not have more than two overlapping ranges
      for (const auto &processed_range : processed_ranges) {
        if (!(last_pos < processed_range.first ||
              first_pos > processed_range.second)) {
          overwrapping_count++;
          if (overwrapping_count > 2) { return true; }
          break; // Only count once per range
        }
      }

      processed_ranges.emplace_back(first_pos, last_pos);
    }

    // After validation, coalesce overlapping ranges as per RFC 9110
    coalesce_ranges(req.ranges, static_cast<size_t>(content_len));
  }

  return false;
}

inline std::pair<size_t, size_t>
get_range_offset_and_length(Range r, size_t content_length) {
  assert(r.first != -1 && r.second != -1);
  assert(0 <= r.first && r.first < static_cast<ssize_t>(content_length));
  assert(r.first <= r.second &&
         r.second < static_cast<ssize_t>(content_length));
  (void)(content_length);
  return std::make_pair(r.first, static_cast<size_t>(r.second - r.first) + 1);
}

inline std::string make_content_range_header_field(
    const std::pair<size_t, size_t> &offset_and_length, size_t content_length) {
  auto st = offset_and_length.first;
  auto ed = st + offset_and_length.second - 1;

  std::string field = "bytes ";
  field += std::to_string(st);
  field += "-";
  field += std::to_string(ed);
  field += "/";
  field += std::to_string(content_length);
  return field;
}

template <typename SToken, typename CToken, typename Content>
bool process_multipart_ranges_data(const Request &req,
                                   const std::string &boundary,
                                   const std::string &content_type,
                                   size_t content_length, SToken stoken,
                                   CToken ctoken, Content content) {
  for (size_t i = 0; i < req.ranges.size(); i++) {
    ctoken("--");
    stoken(boundary);
    ctoken("\r\n");
    if (!content_type.empty()) {
      ctoken("Content-Type: ");
      stoken(content_type);
      ctoken("\r\n");
    }

    auto offset_and_length =
        get_range_offset_and_length(req.ranges[i], content_length);

    ctoken("Content-Range: ");
    stoken(make_content_range_header_field(offset_and_length, content_length));
    ctoken("\r\n");
    ctoken("\r\n");

    if (!content(offset_and_length.first, offset_and_length.second)) {
      return false;
    }
    ctoken("\r\n");
  }

  ctoken("--");
  stoken(boundary);
  ctoken("--");

  return true;
}

inline void make_multipart_ranges_data(const Request &req, Response &res,
                                       const std::string &boundary,
                                       const std::string &content_type,
                                       size_t content_length,
                                       std::string &data) {
  process_multipart_ranges_data(
      req, boundary, content_type, content_length,
      [&](const std::string &token) { data += token; },
      [&](const std::string &token) { data += token; },
      [&](size_t offset, size_t length) {
        assert(offset + length <= content_length);
        data += res.body.substr(offset, length);
        return true;
      });
}

inline size_t get_multipart_ranges_data_length(const Request &req,
                                               const std::string &boundary,
                                               const std::string &content_type,
                                               size_t content_length) {
  size_t data_length = 0;

  process_multipart_ranges_data(
      req, boundary, content_type, content_length,
      [&](const std::string &token) { data_length += token.size(); },
      [&](const std::string &token) { data_length += token.size(); },
      [&](size_t /*offset*/, size_t length) {
        data_length += length;
        return true;
      });

  return data_length;
}

template <typename T>
inline bool
write_multipart_ranges_data(Stream &strm, const Request &req, Response &res,
                            const std::string &boundary,
                            const std::string &content_type,
                            size_t content_length, const T &is_shutting_down) {
  return process_multipart_ranges_data(
      req, boundary, content_type, content_length,
      [&](const std::string &token) { strm.write(token); },
      [&](const std::string &token) { strm.write(token); },
      [&](size_t offset, size_t length) {
        return write_content(strm, res.content_provider_, offset, length,
                             is_shutting_down);
      });
}

inline bool expect_content(const Request &req) {
  if (req.method == "POST" || req.method == "PUT" || req.method == "PATCH" ||
      req.method == "DELETE") {
    return true;
  }
  if (req.has_header("Content-Length") &&
      req.get_header_value_u64("Content-Length") > 0) {
    return true;
  }
  if (is_chunked_transfer_encoding(req.headers)) { return true; }
  return false;
}

inline bool has_crlf(const std::string &s) {
  auto p = s.c_str();
  while (*p) {
    if (*p == '\r' || *p == '\n') { return true; }
    p++;
  }
  return false;
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
inline std::string message_digest(const std::string &s, const EVP_MD *algo) {
  auto context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>(
      EVP_MD_CTX_new(), EVP_MD_CTX_free);

  unsigned int hash_length = 0;
  unsigned char hash[EVP_MAX_MD_SIZE];

  EVP_DigestInit_ex(context.get(), algo, nullptr);
  EVP_DigestUpdate(context.get(), s.c_str(), s.size());
  EVP_DigestFinal_ex(context.get(), hash, &hash_length);

  std::stringstream ss;
  for (auto i = 0u; i < hash_length; ++i) {
    ss << std::hex << std::setw(2) << std::setfill('0')
       << static_cast<unsigned int>(hash[i]);
  }

  return ss.str();
}

inline std::string MD5(const std::string &s) {
  return message_digest(s, EVP_md5());
}

inline std::string SHA_256(const std::string &s) {
  return message_digest(s, EVP_sha256());
}

inline std::string SHA_512(const std::string &s) {
  return message_digest(s, EVP_sha512());
}

inline std::pair<std::string, std::string> make_digest_authentication_header(
    const Request &req, const std::map<std::string, std::string> &auth,
    size_t cnonce_count, const std::string &cnonce, const std::string &username,
    const std::string &password, bool is_proxy = false) {
  std::string nc;
  {
    std::stringstream ss;
    ss << std::setfill('0') << std::setw(8) << std::hex << cnonce_count;
    nc = ss.str();
  }

  std::string qop;
  if (auth.find("qop") != auth.end()) {
    qop = auth.at("qop");
    if (qop.find("auth-int") != std::string::npos) {
      qop = "auth-int";
    } else if (qop.find("auth") != std::string::npos) {
      qop = "auth";
    } else {
      qop.clear();
    }
  }

  std::string algo = "MD5";
  if (auth.find("algorithm") != auth.end()) { algo = auth.at("algorithm"); }

  std::string response;
  {
    auto H = algo == "SHA-256"   ? detail::SHA_256
             : algo == "SHA-512" ? detail::SHA_512
                                 : detail::MD5;

    auto A1 = username + ":" + auth.at("realm") + ":" + password;

    auto A2 = req.method + ":" + req.path;
    if (qop == "auth-int") { A2 += ":" + H(req.body); }

    if (qop.empty()) {
      response = H(H(A1) + ":" + auth.at("nonce") + ":" + H(A2));
    } else {
      response = H(H(A1) + ":" + auth.at("nonce") + ":" + nc + ":" + cnonce +
                   ":" + qop + ":" + H(A2));
    }
  }

  auto opaque = (auth.find("opaque") != auth.end()) ? auth.at("opaque") : "";

  auto field = "Digest username=\"" + username + "\", realm=\"" +
               auth.at("realm") + "\", nonce=\"" + auth.at("nonce") +
               "\", uri=\"" + req.path + "\", algorithm=" + algo +
               (qop.empty() ? ", response=\""
                            : ", qop=" + qop + ", nc=" + nc + ", cnonce=\"" +
                                  cnonce + "\", response=\"") +
               response + "\"" +
               (opaque.empty() ? "" : ", opaque=\"" + opaque + "\"");

  auto key = is_proxy ? "Proxy-Authorization" : "Authorization";
  return std::make_pair(key, field);
}

inline bool is_ssl_peer_could_be_closed(SSL *ssl, socket_t sock) {
  detail::set_nonblocking(sock, true);
  auto se = detail::scope_exit([&]() { detail::set_nonblocking(sock, false); });

  char buf[1];
  return !SSL_peek(ssl, buf, 1) &&
         SSL_get_error(ssl, 0) == SSL_ERROR_ZERO_RETURN;
}

#ifdef _WIN64
// NOTE: This code came up with the following stackoverflow post:
// https://stackoverflow.com/questions/9507184/can-openssl-on-windows-use-the-sy
stem-certificate-store
inline bool load_system_certs_on_windows(X509_STORE *store) {
  auto hStore = CertOpenSystemStoreW((HCRYPTPROV_LEGACY)NULL, L"ROOT");
  if (!hStore) { return false; }

  auto result = false;
  PCCERT_CONTEXT pContext = NULL;
  while ((pContext = CertEnumCertificatesInStore(hStore, pContext)) !=
         nullptr) {
    auto encoded_cert =
        static_cast<const unsigned char *>(pContext->pbCertEncoded);

    auto x509 = d2i_X509(NULL, &encoded_cert, pContext->cbCertEncoded);
    if (x509) {
      X509_STORE_add_cert(store, x509);
      X509_free(x509);
      result = true;
    }
  }

  CertFreeCertificateContext(pContext);
  CertCloseStore(hStore, 0);

  return result;
}
#elif defined(CPPHTTPLIB_USE_CERTS_FROM_MACOSX_KEYCHAIN) &&                    \
    defined(TARGET_OS_OSX)
template <typename T>
using CFObjectPtr =
    std::unique_ptr<typename std::remove_pointer<T>::type, void (*)(CFTypeRef)>;

inline void cf_object_ptr_deleter(CFTypeRef obj) {
  if (obj) { CFRelease(obj); }
}

inline bool retrieve_certs_from_keychain(CFObjectPtr<CFArrayRef> &certs) {
  CFStringRef keys[] = {kSecClass, kSecMatchLimit, kSecReturnRef};
  CFTypeRef values[] = {kSecClassCertificate, kSecMatchLimitAll,
                        kCFBooleanTrue};

  CFObjectPtr<CFDictionaryRef> query(
      CFDictionaryCreate(nullptr, reinterpret_cast<const void **>(keys), values,
                         sizeof(keys) / sizeof(keys[0]),
                         &kCFTypeDictionaryKeyCallBacks,
                         &kCFTypeDictionaryValueCallBacks),
      cf_object_ptr_deleter);

  if (!query) { return false; }

  CFTypeRef security_items = nullptr;
  if (SecItemCopyMatching(query.get(), &security_items) != errSecSuccess ||
      CFArrayGetTypeID() != CFGetTypeID(security_items)) {
    return false;
  }

  certs.reset(reinterpret_cast<CFArrayRef>(security_items));
  return true;
}

inline bool retrieve_root_certs_from_keychain(CFObjectPtr<CFArrayRef> &certs) {
  CFArrayRef root_security_items = nullptr;
  if (SecTrustCopyAnchorCertificates(&root_security_items) != errSecSuccess) {
    return false;
  }

  certs.reset(root_security_
