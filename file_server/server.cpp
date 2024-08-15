#include <iostream>
#include <string>
#include <regex>
#include <fstream>
#include <cpprest/http_listener.h>
#include <cpprest/containerstream.h>

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
    auto bufferStream = std::make_shared<container_buffer<std::vector<uint8_t>>>();

    // Read the request body into the buffer.
    pplx::task<void> requestTask = request.body().read_to_end(bufferStream->create_ostream().streambuf())
    .then([=](size_t bytesRead) {
        // Extract the content of the buffer.
        auto& data = bufferStream->collection();
        std::string content(data.begin(), data.end());

        // Use regex to extract the boundary, filename, and file content.
        std::regex boundary_regex("--([^\r\n]+)");
        std::regex filename_regex("filename=\"([^\"]+)\"");
        std::regex content_regex("\r\n\r\n(.*)");

        std::smatch boundary_match;
        std::smatch filename_match;
        std::smatch content_match;

        std::string boundary;
        std::string filename;
        std::string file_content;

        if (std::regex_search(content, boundary_match, boundary_regex)) {
            boundary = boundary_match[1].str();
        }

        if (std::regex_search(content, filename_match, filename_regex)) {
            filename = filename_match[1].str();
        }

        // Find the start of the file content
        size_t content_start = content.find("\r\n\r\n");
        if (content_start != std::string::npos) {
            content_start += 4; // Skip past the "\r\n\r\n"
            size_t content_end = content.find("--" + boundary, content_start);
            if (content_end != std::string::npos) {
                file_content = content.substr(content_start, content_end - content_start);
            }
        }

        // Save the file content to the new file
        std::ofstream outfile(filename, std::ios::binary);
        if (outfile.is_open()) {
            outfile.write(file_content.c_str(), file_content.size());
            outfile.close();
        } else {
            throw std::runtime_error("Failed to open file for writing");
        }

        // Print the new filename and file content.
        std::cout << "Generated filename:\n" << filename << std::endl;
        std::cout << "File content:\n" << file_content << std::endl;

        // Reply to the client.
        request.reply(status_codes::OK, U("File uploaded successfully.\n"));
    })
    .then([=](pplx::task<void> t) {
        try {
            t.get();
        } catch (const std::exception& e) {
            request.reply(status_codes::InternalError, U("File upload failed.\n"));
        }
    });

    // Wait for the task to complete.
    try {
        requestTask.wait();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

