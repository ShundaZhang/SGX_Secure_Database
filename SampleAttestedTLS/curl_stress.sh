#!/bin/bash
#curl -X POST -H Content-Type: application/json -d {"data": "show databases;use $edgeless;show tables;desc config;"} http://10.239.166.47:8088/sql

for i in {1..256}
do
  curl -X POST -H "Content-Type: application/json" \
  -d '{"data": "show databases;use $edgeless;show tables;desc config;"}' \
  http://10.239.166.47:8088/sql &
done

# Wait for all background processes to finish
wait

