curl -v --noproxy '*' -F "file=@example.txt" https://10.239.166.47:8443/upload --cacert ../server.crt
curl -v --noproxy '*' -F "file=@example2.txt" https://10.239.166.47:8443/upload --cacert ../server.crt
