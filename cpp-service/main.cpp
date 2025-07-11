#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"
#include <iostream>

int main(void) {
    httplib::Server svr;

    svr.Get("/status", [](const httplib::Request &, httplib::Response &res) {
        res.set_content("{\"status\": \"OK\", \"service\": \"C++\"}", "application/json");
    });

    std::cout << "C++ Service listening on port 8080..." << std::endl;
    svr.listen("0.0.0.0", 8080);

    return 0;
}
