all:
	gcc -o tls_server tls_server.c -lssl -lcrypto
	gcc -o tls_client tls_client.c -lssl -lcrypto

clean:
	@rm tls_server tls_client
