#!/bin/bash
#mysql -uroot -h127.0.0.1 -P3307 --ssl-ca edb.pem --ssl-cert cert.pem --ssl-key key.pem -ppassword

for i in {1..100}
do
	mysql -uroot -h127.0.0.1 -P3307 --ssl-ca ../edb.pem --ssl-cert ../cert.pem --ssl-key ../key.pem -ppassword &
done

# Wait for all background processes to finish
wait
