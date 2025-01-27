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
#include <cpprest/containerstream.h>
#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include <regex>

#include "sgx_tprotected_fs.h"

#define TLS_SERVER_NAME "localhost"
#define TLS_SERVER_PORT "12340"

/* Global EID shared by multiple threads */
sgx_enclave_id_t client_global_eid = 0;

void terminate_enclave()
{
	sgx_destroy_enclave(client_global_eid);
	printf("Host: Enclave successfully terminated.\n");
}

//Connection Pool Code
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <limits.h>
#include <pthread.h>
#include <semaphore.h>
#include <time.h>
#include <endian.h>

#define DB_POOL_CONN_COUNT        (24U)
#define DEFAULT_MUTEX_TIMEOUT_SEC (30)

static pthread_mutex_t db_mutex;
static pthread_rwlock_t db_rw_lock;
static sem_t db_sem;
static void* mysql_conns[DB_POOL_CONN_COUNT] = {NULL}; //volatile
static volatile int mysql_conns_busy[DB_POOL_CONN_COUNT] = {0};

static volatile int is_thread_safe = 0;
static volatile int is_inited = 0;
static volatile int is_open = 0;
static volatile int is_closed = 1;


int db_close(void *pdb)
{
	size_t i;
	int ready;
	int ret;

	if (!is_inited) {
		return -1;
	}

	if (pthread_rwlock_wrlock(&db_rw_lock) != 0) {
		return -1;
	}

	if (is_closed) {
		pthread_rwlock_unlock(&db_rw_lock);
		return 0;
	}

	/*
	 * after this the `db_get_conn` function won't return any more
	 * connections from the pool until `is_open` becomes 1
	 *
	 * by setting the `is_closed` to 1 we can inform the application
	 * the connections was closed intentionally and there is no need
	 * to reconnect
	 */
	is_open = 0;
	is_closed = 1;

	pthread_rwlock_unlock(&db_rw_lock);

	/*
	 * try to wait for all the connections from the pool that are being
	 * used and close them
	 *
	 * no more connections will be returned from the pool by the
	 * `db_get_conn` funtion until `db_connect` is called again
	 */
	ready = 0;
	while (!ready) {
		for (i = 0U; i < DB_POOL_CONN_COUNT; i++) {
			ready = 1;

			if (pthread_mutex_lock(&db_mutex) != 0) {
				return -1;
			}
			if (mysql_conns_busy[i] == 1) {
				pthread_mutex_unlock(&db_mutex);

				if (sem_wait(&db_sem) != 0) {
					return -1;
				}
				ready = 0;
			} else {
				sgx_status_t result = close_db_connect(client_global_eid, &ret, pdb);
				if (result != SGX_SUCCESS || ret != 0)
				{
					printf("Host: close_db_connect failed! result=%d, ret=%d\n", result, ret);
					terminate_enclave();
					return -1;
				}

				pthread_mutex_unlock(&db_mutex);
			}

			if (!ready) {
				break;
			}
		}
	}

	return 0;
}


void db_close_all()
{
	int ret;
	for (int i = 0U; i < DB_POOL_CONN_COUNT; i++)
	{
		if (mysql_conns[i]) {
			printf( "Exiting, closing connection %d\n", i);
			sgx_status_t result = close_db_connect(client_global_eid, &ret, mysql_conns[i]);
			if (result != SGX_SUCCESS || ret != 0)
			{
				printf("Host: close_db_connect failed\n");
				terminate_enclave();
			}

		}
	}
}

int db_open(const char *host, const char *port)
{
	size_t i;
	int ret;

	if (!is_inited) {

		is_thread_safe = 1;

		if (pthread_mutex_init(&db_mutex, NULL) != 0) {
			return -1;
		}

		if (pthread_rwlock_init(&db_rw_lock, NULL) != 0) {
			pthread_mutex_destroy(&db_mutex);
			return -1;
		}

		if (sem_init(&db_sem, 0, DB_POOL_CONN_COUNT) != 0) {
			pthread_rwlock_destroy(&db_rw_lock);
			pthread_mutex_destroy(&db_mutex);
			return -1;
		}

		is_inited = 1;
	}

	if (pthread_mutex_lock(&db_mutex) != 0) {
		return -1;
	}

	for (i = 0U; i < DB_POOL_CONN_COUNT; i++) {
		if (!mysql_conns[i]) {
			sgx_status_t result = init_db_connect(client_global_eid, &ret, host, port, &(mysql_conns[i]));
			//printf( "result = %d, ret = %d, mysql_conns[%u] = %u\n", result, ret, i, mysql_conns[i] );
			if (!mysql_conns[i] || result != SGX_SUCCESS || ret != 0) {
				/*
				 * close all the connections
				 */
				for (;;) {
					if (mysql_conns[i]) {
						db_close(mysql_conns[i]);
						mysql_conns[i] = NULL;
					}

					if (i == 0U) {
						break;
					} else {
						i--;
					}
				}
				pthread_mutex_unlock(&db_mutex);

				return -1;
			}
		} else {
			/*
			 * reuse a previously created connection
			 *
			 * we are setting the MYSQL_OPT_RECONNECT option when
			 * creating a connection so a simple ping should do a
			 * reconnect (given that the server is responding) if the
			 * connection was lost for some reason (i.e. timeout)
			 */
			//if (mysql_ping(mysql_conns[i]) != 0) {
			//    pthread_mutex_unlock(&db_mutex);

			//    return -1;
		}
	}

	if (pthread_rwlock_wrlock(&db_rw_lock) != 0) {
		pthread_mutex_unlock(&db_mutex);

		return -1;
	}

	is_open = 1;
	is_closed = 0;

	pthread_rwlock_unlock(&db_rw_lock);

	pthread_mutex_unlock(&db_mutex);

	return 0;
}

int db_is_open(void) {
	int result;

	if (!is_inited) {
		return 0;
	}

	if (pthread_rwlock_rdlock(&db_rw_lock) != 0) {
		return -1;
	}

	result = is_open;

	pthread_rwlock_unlock(&db_rw_lock);

	return result;
}

int db_is_closed(void)
{
	int result;

	if (!is_inited) {
		return 1;
	}

	if (pthread_rwlock_rdlock(&db_rw_lock) != 0) {
		return -1;
	}

	result = is_closed;

	pthread_rwlock_unlock(&db_rw_lock);

	return result;
}

void *db_get_conn(void)
{
	size_t i;
	struct timespec tmo_timespec;
	void *mysql_conn = NULL;

	if (!is_inited) {
		return NULL;
	}

	if (pthread_rwlock_rdlock(&db_rw_lock) != 0) {
		return NULL;
	}

	if (!is_open) {
		pthread_rwlock_unlock(&db_rw_lock);

		return NULL;
	}

	pthread_rwlock_unlock(&db_rw_lock);

	if (sem_wait(&db_sem) != 0) {
		return NULL;
	}

	if (clock_gettime(CLOCK_REALTIME, &tmo_timespec) != 0) {
		if (sem_post(&db_sem) != 0) {
			/* ignore the error, we are already in erroneous state */
		}
		return NULL;
	}

	tmo_timespec.tv_sec += DEFAULT_MUTEX_TIMEOUT_SEC;
	if (pthread_mutex_timedlock(&db_mutex, &tmo_timespec) != 0) {
		if (sem_post(&db_sem) != 0) {
			/* ignore the error, we are already in erroneous state */
		}
		return NULL;
	}

	if (pthread_rwlock_rdlock(&db_rw_lock) != 0) {
		return NULL;
	}

	/*
	 * checking another time because it's possible that db_close was
	 * working while we were waiting on the mutex or a connection was
	 * closed for another reason
	 */
	if (!is_open) {
		pthread_rwlock_unlock(&db_rw_lock);
		pthread_mutex_unlock(&db_mutex);

		if (sem_post(&db_sem) != 0) {
			/* ignore the error, we are already in erroneous state */
		}
		return NULL;
	}

	pthread_rwlock_unlock(&db_rw_lock);

	for (i = 0U; i < DB_POOL_CONN_COUNT; i++) {
		if (!mysql_conns_busy[i]) {
			mysql_conns_busy[i] = 1;
			mysql_conn = mysql_conns[i];
			break;
		}
	}

	if (!mysql_conn) {
		pthread_mutex_unlock(&db_mutex);
		if (sem_post(&db_sem) != 0) {
			/* ignore the error, we are already in erroneous state */
		}
		return NULL;
	}

	pthread_mutex_unlock(&db_mutex);


	return mysql_conn;
}

int db_post_conn(void *mysql_conn)
{
	size_t i;
	int found;

	if (!is_inited) {
		return -1;
	}

	if (!mysql_conn) {
		return -1;
	}

	if (pthread_mutex_lock(&db_mutex) != 0) {
		return -1;
	}

	for (i = 0U, found = 0; i < DB_POOL_CONN_COUNT; i++) {
		if (mysql_conns_busy[i]) {
			mysql_conns[i] = mysql_conn;
			mysql_conns_busy[i] = 0;
			found = 1;
			break;
		}
	}

	if (!found) {
		pthread_mutex_unlock(&db_mutex);

		return -1;
	}

	pthread_mutex_unlock(&db_mutex);

	if (sem_post(&db_sem) != 0) {
		return -1;
	}

	return 0;
}
//End of Connection Pool Code


//Restful Server

using namespace web;
using namespace web::http;
using namespace web::http::experimental::listener;
using namespace concurrency::streams;

std::string sql_server = "127.0.0.1";
std::string sql_port = "3307";

std::string uploaded_dir = "./uploaded/";
std::string enc_suffix = ".enc";

void handle_file_upload(http_request request)
{
    auto bufferStream = std::make_shared<container_buffer<std::vector<uint8_t>>>();

    // Read the request body into the buffer.
    pplx::task<void> requestTask = request.body().read_to_end(bufferStream->create_ostream().streambuf())
    .then([=](size_t bytesRead) {
        // Extract the content of the buffer.
        auto& data = bufferStream->collection();
        std::vector<uint8_t> content(data.begin(), data.end());

	// Convert vector to string for regex processing
        std::string content_str(content.begin(), content.end());

        // Use regex to extract the boundary, filename, and file content.
        std::regex boundary_regex("--([^\r\n]+)");
        std::regex filename_regex("filename=\"([^\"]+)\"");
        std::regex content_regex("\r\n\r\n(.*)");

        std::smatch boundary_match;
        std::smatch filename_match;
        std::smatch content_match;

        std::string boundary;
        std::string filename;
        std::vector<uint8_t> file_content;

        if (std::regex_search(content_str, boundary_match, boundary_regex)) {
            boundary = boundary_match[1].str();
        }

        if (std::regex_search(content_str, filename_match, filename_regex)) {
            filename = filename_match[1].str();
        }

        // Find the start of the file content
        size_t content_start = content_str.find("\r\n\r\n");
        if (content_start != std::string::npos) {
            content_start += 4; // Skip past the "\r\n\r\n"
            size_t content_end = content_str.find("--" + boundary, content_start);
            if (content_end != std::string::npos) {
                file_content.assign(content.begin() + content_start, content.begin() + content_end);
            }
        }

        // Generate the new filename with directory prefix and .enc extension
        filename = uploaded_dir + filename + enc_suffix;

        // Save the file content to the new file
        //std::ofstream outfile(filename, std::ios::binary);
        //if (outfile.is_open()) {
        //    outfile.write(reinterpret_cast<const char*>(file_content.data()), file_content.size());
        //    outfile.close();
        //} else {
        //    throw std::runtime_error("Failed to open file for writing");
        //}

	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
        uint64_t file_size = 0;
        SGX_FILE* fp;
        const char* fname = filename.c_str();
        const char* mode = "wb";

	//file Open
        ret = ecall_file_open(client_global_eid, &fp, fname, mode);

	//Write to file
        size_t sizeOfWrite = 0;
        ret = ecall_file_write(client_global_eid, &sizeOfWrite, fp, reinterpret_cast<const char*>(file_content.data()), file_content.size());
        printf("Size of Write =  %ld\n", sizeOfWrite);

	int32_t fileHandle;
        ret = ecall_file_close(client_global_eid, &fileHandle, fp);

        // Print the new filename and file content size.
        std::cout << "Generated filename: " << filename << std::endl;
        std::cout << "File content size: " << file_content.size() << " bytes" << std::endl;

        // Reply to the client.
        request.reply(status_codes::OK, U("File uploaded successfully."));
    })
    .then([=](pplx::task<void> t) {
        try {
            t.get();
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

void handle_file_read(http_request request)
{
    ucout << "Received POST request to /read" << std::endl;

    // Extract JSON data from the request
    request.extract_json()
    .then([&request](json::value data) {
        // Get the filename from the JSON
        utility::string_t filename = data[U("filename")].as_string();

        // Generate the full path with directory prefix and .enc extension
        filename = uploaded_dir + filename + enc_suffix;

        // Read the file content
        //std::ifstream infile(filename, std::ios::binary);
        //if (!infile.is_open()) {
        //    request.reply(status_codes::NotFound, U("File not found."));
        //    return;
        //}
        
	//std::vector<uint8_t> file_content((std::istreambuf_iterator<char>(infile)), std::istreambuf_iterator<char>());
        //infile.close();

	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	uint64_t file_size = 0;
        SGX_FILE* fp;
        const char* fname = filename.c_str();
        const char* mode = "rb";

        //file Open
        ret = ecall_file_open(client_global_eid, &fp, fname, mode);

	//Read from File
        ret = ecall_file_get_file_size(client_global_eid, &file_size, fp);
	std::vector<uint8_t> file_content(file_size);
        
	size_t sizeOfRead = 0;
        ret = ecall_file_read(client_global_eid, &sizeOfRead, fp, reinterpret_cast<char*>(file_content.data()), file_size);
        printf("Size of Read = %ld\n", sizeOfRead);

	int32_t fileHandle;
        ret = ecall_file_close(client_global_eid, &fileHandle, fp);


        // Construct JSON response
        json::value response;
        response[U("content")] = json::value::string(utility::conversions::to_base64(file_content));

        // Send the file content as response
        request.reply(status_codes::OK, response);
    })
    .wait();
}

void handle_sql(http_request request) {
	ucout << "Received POST request to /sql" << std::endl;

	// Extract JSON data from the request
	request.extract_json()
		.then([&request](json::value data) {
				// Get the SQL data from the JSON
				utility::string_t sql_data = data[U("data")].as_string();

				// Add the query "SHOW STATUS LIKE 'Ssl_cipher';" to SQL data
				sql_data += "SHOW STATUS LIKE 'Ssl_cipher';";

				char *input_file = (char *)malloc(4096);
				char *output_file = (char *)malloc(4096);

				if (input_file == nullptr || output_file == nullptr) {
					std::cerr << "Memory allocation failed" << std::endl;
				}

				size_t pos = 0;
				while ((pos = sql_data.find(';', pos)) != std::string::npos) {
					sql_data.insert(pos + 1, "\n");
					++pos;
				}

				if (sql_data.size() >= 4096) {
					std::cerr << "Data exceeds buffer size" << std::endl;
					free(input_file);
				}

				std::strncpy(input_file, sql_data.c_str(), 4096);

				sgx_status_t result = SGX_SUCCESS;
				int ret = 1;
				printf("Host: launch TLS client to initiate TLS connection\n");

				void *pdb = NULL; 

				pdb = db_get_conn();
				if (!pdb)
				{
					printf("Get connection failed\n");
				}

				result = exec_db_sql(client_global_eid, &ret, input_file, output_file, pdb);
				if (result != SGX_SUCCESS || ret != 0)
				{
					printf("Host: exec_db_sql failed with result=%d, ret=%d.\n", result, ret);
					//Stop the enclave, only for Debug
					//terminate_enclave();
				}
				db_post_conn(pdb);

				//result = close_db_connect(client_global_eid, &ret, pdb);
				//if (result != SGX_SUCCESS || ret != 0)
				//{
				//	printf("Host: close_db_connect failed\n");
				//	terminate_enclave();
				//}
				//pdb = NULL;

				// Read client output
				std::string output_content(output_file);

				free(input_file);
				free(output_file);
				
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

	ret = db_open(sql_server.c_str(), sql_port.c_str());
	if ( ret != 0 )
	{
		printf("DB Open Error!");
		terminate_enclave();
		return -1;
	}

	//Lauch Restful Server

	http_listener sql_listener(U("http://0.0.0.0:8088/sql"));
	sql_listener.support(methods::POST, handle_sql);
	
	http_listener_config config;
	config.set_ssl_context_callback([](boost::asio::ssl::context& ctx) {
			ctx.set_options(boost::asio::ssl::context::default_workarounds);
			ctx.use_certificate_chain_file("file_server.pem");
			ctx.use_private_key_file("file_server.key", boost::asio::ssl::context::pem);
			});

	http_listener file_listener(U("https://0.0.0.0:8443/upload"), config);
	file_listener.support(methods::POST, handle_file_upload);

	http_listener read_listener(U("https://0.0.0.0:8443/read"));
	read_listener.support(methods::POST, handle_file_read);

	try {
		sql_listener.open().then([&sql_listener]() {
				ucout << "Listening for requests at: " << sql_listener.uri().to_string() << std::endl;
				}).wait();

		file_listener.open().then([&file_listener]() {
				ucout << "Listening for file uploads at: " << file_listener.uri().to_string() << std::endl;
				}).wait();

		read_listener.open().then([&read_listener]() {
				ucout << "Listening for file read requests at: " << read_listener.uri().to_string() << std::endl;
				}).wait();

		std::cout << "Press Enter to exit." << std::endl;
		std::string line;
		std::getline(std::cin, line);
	} catch (const std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}

	sql_listener.close().wait();
	file_listener.close().wait();
	read_listener.close().wait();	

	db_close_all();
	terminate_enclave();
	return 0;
}
