#!/bin/bash
#mysql -uroot -h127.0.0.1 -P3306 -ppassword

start_time=$(date +%s)

for i in {1..10000}
do
	#mysql -h 127.0.0.1 -P 3306 -u root -ppassword -e "show databases; use mysql; show tables; desc user;SHOW STATUS LIKE 'Ssl_cipher';"  &
	mysql -h 10.239.166.47 -P 3306 -u user -ppassword -e "show databases; use mysql; show tables; desc user;SHOW STATUS LIKE 'Ssl_cipher';" &
done

# Wait for all background processes to finish
wait

end_time=$(date +%s)

elapsed_time=$((end_time - start_time))
echo "Total time taken: ${elapsed_time} seconds"
