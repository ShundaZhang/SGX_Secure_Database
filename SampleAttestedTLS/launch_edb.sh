docker rm my-edb
docker run -t --name my-edb -e PCCS_URL=https://10.239.166.47:8081/sgx/certification/v4/ -p3307:3306 -p8080:8080 --device /dev/sgx_enclave --device /dev/sgx_provision ghcr.io/edgelesssys/edgelessdb-sgx-1gb
