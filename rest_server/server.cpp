//g++ -std=c++11 -o server server.cpp -lboost_system -lcpprest -lssl -lcrypto -pthread

//Request Examples:
// curl http://10.239.166.47:8088
// curl -X POST -H "Content-Type: application/json" -d '{"data": "show databases;"}' http://10.239.166.47:8088/sql
// curl -X POST -H "Content-Type: application/json" -d '{"data": "show databases;use $edgeless;show tables;desc config;"}' http://10.239.166.47:8088/sql


#include <cpprest/http_listener.h>
#include <cpprest/json.h>
#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>

using namespace web;
using namespace web::http;
using namespace web::http::experimental::listener;

void handle_sql(http_request request) {
    ucout << "Received POST request to /sql" << std::endl;

    // Extract JSON data from the request
    request.extract_json()
    .then([&request](json::value data) {
        // Get the SQL data from the JSON
        utility::string_t sql_data = data[U("data")].as_string();

        // Generate a random filename
        std::string filename = std::to_string(rand()) + ".sql";
        std::string input_file = "/tmp/" + filename + ".in";
        std::string output_file = "/tmp/" + filename + ".out";

	std::string sql_client = "../SampleAttestedTLS/client/host/tls_client_host";
	std::string sql_enclave = "../SampleAttestedTLS/client/enc/tls_client_enclave.signed.so";

        // Write SQL data to input file
	std::ofstream input_stream(input_file);
        size_t pos = 0;
        while ((pos = sql_data.find(';', pos)) != std::string::npos) {
            sql_data.insert(pos + 1, "\n");
            ++pos;
        }
        input_stream << sql_data;
        input_stream.close();

        // Call client program
        std::string command = sql_client + " " + sql_enclave + " -server:127.0.0.1 -port:3307 -in:" + input_file + " -out:" + output_file;
        system(command.c_str());

        // Read client output
        std::ifstream output_stream(output_file);
        std::string output_content((std::istreambuf_iterator<char>(output_stream)), std::istreambuf_iterator<char>());
        output_stream.close();

	// Construct JSON response
        json::value response;
        response[U("output")] = json::value::string(U(output_content));

        // Send the output content as response
        request.reply(status_codes::OK, response);
    })
    .wait();
}

int main() {
    srand(time(NULL));

    http_listener listener(U("http://0.0.0.0:8088/sql"));
    listener.support(methods::POST, handle_sql);

    try {
        listener.open().then([&listener]() {
            ucout << "Listening for requests at: " << listener.uri().to_string() << std::endl;
        }).wait();

        std::cout << "Press Enter to exit." << std::endl;
        std::string line;
        std::getline(std::cin, line);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    listener.close().wait();

    return 0;
}

