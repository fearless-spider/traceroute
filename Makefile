FLAGS = -pedantic -Wall

all : traceroute.o
	g++ -o traceroute traceroute.o $(FLAGS)

traceroute.o : traceroute.cc
	g++ -c -o traceroute.o traceroute.cc $(FLAGS)
	
run :
	./traceroute

clean :
	rm -f traceroute.o
	rm -f traceroute
	
