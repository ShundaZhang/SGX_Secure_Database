#include <iostream>
#include <string>
#include <cpprest/http_listener.h>
#include <cpprest/filestream.h>
#include <cpprest/containerstream.h>
#include <cpprest/producerconsumerstream.h>

using namespace web;
using namespace web::http;
using namespace web::http::experimental::listener;
using namespace concurrency::streams;

void handle_file_upload(http_request request);

int main()
{
    // 配置 HTTPS
    http_listener_config config;
    config.set_ssl_context_callback([](boost::asio::ssl::context& ctx) {
        ctx.set_options(boost::asio::ssl::context::default_workarounds);
        ctx.use_certificate_chain_file("server.pem");
        ctx.use_private_key_file("server.key", boost::asio::ssl::context::pem);
    });

    http_listener file_listener(U("https://0.0.0.0:8443/upload"), config);
    file_listener.support(methods::POST, handle_file_upload);

    try {
        file_listener.open().then([&file_listener]() {
            ucout << "Listening for file uploads at: " << file_listener.uri().to_string() << std::endl;
        }).wait();

        std::cout << "Press Enter to exit." << std::endl;
        std::string line;
        std::getline(std::cin, line);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    file_listener.close().wait();
    return 0;
}

void handle_file_upload(http_request request)
{
    auto fileStream = std::make_shared<ostream>();

    // Open stream to output file.
    pplx::task<void> requestTask = fstream::open_ostream(U("uploaded_file"))
    .then([=](ostream outFile) {
        *fileStream = outFile;

        // Read the request body.
        return request.body().read_to_end(fileStream->streambuf());
    })
    .then([=](size_t) {
        // Close the file stream.
        return fileStream->close();
    })
    .then([=](pplx::task<void> t) {
        try {
            t.get();
            request.reply(status_codes::OK, U("File uploaded successfully."));
        } catch (const std::exception& e) {
            request.reply(status_codes::InternalError, U("File upload failed."));
        }
    });

    // Wait for the task to complete.
    try {
        requestTask.wait();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

