cp client/host/file_server.* .
client/host/tls_client_host client/enc/tls_client_enclave.signed.so -server:127.0.0.1 -port:3307
rm file_server.* -f
