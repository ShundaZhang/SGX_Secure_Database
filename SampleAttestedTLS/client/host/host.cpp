/**
*
* MIT License
*
* Copyright (c) Open Enclave SDK contributors.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE
*
*/

#include "sgx_urts.h"
#include <stdio.h>
#include <netdb.h>
#include "tls_client_u.h"
#include <sys/socket.h>
#include <sys/types.h>

#include <cpprest/http_listener.h>
#include <cpprest/json.h>
#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>

#define TLS_SERVER_NAME "localhost"
#define TLS_SERVER_PORT "12340"

/* Global EID shared by multiple threads */
sgx_enclave_id_t client_global_eid = 0;

void terminate_enclave()
{
    sgx_destroy_enclave(client_global_eid);
    printf("Host: Enclave successfully terminated.\n");
}


//Restful Server

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

        // Add the query "SHOW STATUS LIKE 'Ssl_cipher';" to SQL data
        sql_data += "SHOW STATUS LIKE 'Ssl_cipher';";

        // Generate a random filename
        std::string filename = std::to_string(rand()) + ".sql";
        std::string input_file = "/tmp/" + filename + ".in";
        std::string output_file = "/tmp/" + filename + ".out";

        std::string sql_server = "127.0.0.1";
        std::string sql_port = "3307";

        // Write SQL data to input file
        std::ofstream input_stream(input_file);
        size_t pos = 0;
        while ((pos = sql_data.find(';', pos)) != std::string::npos) {
            sql_data.insert(pos + 1, "\n");
            ++pos;
        }
        input_stream << sql_data;
        input_stream.close();

	sgx_status_t result = SGX_SUCCESS;
	int ret = 1;
	printf("Host: launch TLS client to initiate TLS connection\n");
	result = launch_tls_client(client_global_eid, &ret, sql_server.c_str(), sql_port.c_str(), input_file.c_str(), output_file.c_str());
	if (result != SGX_SUCCESS || ret != 0)
	{
		printf("Host: launch_tls_client failed\n");
		terminate_enclave();
	}
        
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



typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
        printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

sgx_status_t initialize_enclave(const char *enclave_path)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    // the 1st parameter should be CLIENT_ENCLAVE_FILENAME
    ret = sgx_create_enclave(enclave_path, SGX_DEBUG_FLAG, NULL, NULL, &client_global_eid, NULL);
    printf("Client Enc: Enclave library %s\n", enclave_path);

    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        return ret;
    }
    return ret;
}

int main(int argc, const char* argv[])
{
    sgx_status_t result = SGX_SUCCESS;
    int ret = 1;
    char* server_name = NULL;
    char* server_port = NULL;
    char* input_file = NULL;
    char* output_file = NULL;
    
    printf("Host: Creating client enclave\n");
    result = initialize_enclave(argv[1]);
    if (result != SGX_SUCCESS)
    {
	terminate_enclave();
	return -1;
    }

    //Lauch Restful Server
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

    terminate_enclave();
    return 0;
}
