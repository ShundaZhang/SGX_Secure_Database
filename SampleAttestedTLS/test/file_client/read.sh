curl -v --noproxy '*' -X POST https://10.239.166.47:8443/read -H "Content-Type: application/json" -d '{"filename": "example.txt"}' --cacert ../../client/host/file_server.crt
curl -v --noproxy '*' -X POST https://10.239.166.47:8443/read -H "Content-Type: application/json" -d '{"filename": "example2.txt"}' --cacert ../../client/host/file_server.crt
