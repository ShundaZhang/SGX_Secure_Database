nanomysql : nanomysql.cpp
	g++ -lstdc++ -o nanomysql nanomysql.cpp

clean:
	@rm nanomysql
