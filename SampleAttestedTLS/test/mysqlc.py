import time
import concurrent.futures
import pymysql

# MySQL connection details
host = '10.239.166.47'
port = 3306
user = 'user'
password = 'password'
query = ["show databases;", "use mysql;", "show tables;", "desc user;", "SHOW STATUS LIKE 'Ssl_cipher';"]

n_worker = 128
num = 10000

def execute_query():
    result = []
    try:
        connection = pymysql.connect(host=host, port=port, user=user, password=password)
        with connection.cursor() as cursor:
            for q in query:
                cursor.execute(q)
                result.append(cursor.fetchall())
            return result
    except Exception as e:
        print(f"Error: {e}")
    finally:
        connection.close()

def main():
    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=n_worker) as executor:
        futures = [executor.submit(execute_query) for _ in range(num)]
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                # Process the result if needed
                print(result)
            except Exception as e:
                print(f"Error: {e}")

    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"Total time taken: {elapsed_time} seconds")

if __name__ == "__main__":
    main()

