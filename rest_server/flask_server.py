#Request Examples:
# curl http://10.239.166.47:8088
# curl -X POST -H "Content-Type: application/json" -d '{"data": "show databases;"}' http://10.239.166.47:8088/sql
# curl -X POST -H "Content-Type: application/json" -d '{"data": "show databases;use $edgeless;show tables;desc config;"}' http://10.239.166.47:8088/sql

import os
import random
import subprocess
from flask import Flask, request, jsonify

sql_client = "../SampleAttestedTLS/client/host/tls_client_host"
sql_enclave = "../SampleAttestedTLS/client/enc/tls_client_enclave.signed.so"
server_name = "127.0.0.1"
port = "3307"

app = Flask(__name__)

@app.route('/sql', methods=['GET', 'POST'])
def sql():
    if request.method == 'GET':
        return 'This is a GET request'
    elif request.method == 'POST':
        data = request.get_json()
        sql_data = data.get('data')
        if not sql_data:
            return 'No SQL data provided'

        # Generate a random filename
        filename = f"{random.randint(1, 1000000)}.sql"
        input_file = "/tmp/"+f"{filename}.in"
        output_file = "/tmp/"+f"{filename}.out"

        # Write SQL data to input file
        with open(input_file, 'w') as f:
            f.write(sql_data.replace(';', ';\n'))

        # Call client program
        subprocess.run([sql_client, sql_enclave, "-server:"+server_name, "-port:"+port, "-in:"+input_file, "-out:"+output_file])

        # Read client output
        with open(output_file, 'r') as f:
            output_content = f.read()

        return jsonify({'output': output_content})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8088, debug=True)

