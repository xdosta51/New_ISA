all:
	g++  -Wall -Wextra -Werror -pedantic  dns.cpp -o dns 
clean:
	rm dns
run:
	./dns -s dns.google -p 1234 -f filter.txt 
test:
	./test.sh
