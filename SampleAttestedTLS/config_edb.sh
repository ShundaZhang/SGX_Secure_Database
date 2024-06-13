era -c edgelessdb-sgx.json -h localhost:8080 -output-root edb.pem -allow-tcb-status=OutOfDateConfigurationNeeded
curl --cacert edb.pem --data-binary @manifest.json https://localhost:8080/manifest

sleep 32

mysql -uroot -h127.0.0.1 -P3307 --ssl-ca edb.pem --ssl-cert cert.pem --ssl-key key.pem < init.sql
