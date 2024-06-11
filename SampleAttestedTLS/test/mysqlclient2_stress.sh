#!/bin/bash
#mysql -uroot -h127.0.0.1 -P3306 -ppassword

#for i in {1..1000}
for i in {1..100}
do
	mysql -uroot -h127.0.0.1 -P3306 -ppassword  &
done

# Wait for all background processes to finish
wait
