#!/bin/bash
#curl -X POST -H "Content-Type: application/json" -d '{"data": "show databases;use $edgeless;show tables;desc config;"}' http://10.239.166.47:8088/sql

start_time=$(date +%s)

for i in {1..10000}
do
  curl --noproxy '*' -X POST -H "Content-Type: application/json" \
  -d '{"data": "show databases;use $edgeless;show tables;desc config;"}' \
  http://10.239.166.47:8088/sql &
done

# Wait for all background processes to finish
wait

end_time=$(date +%s)

elapsed_time=$((end_time - start_time))
echo "Total time taken: ${elapsed_time} seconds"
