LIB=TEA


all: lib$(LIB).a

lib$(LIB).a: $(LIB).o
	ar -cvq lib$(LIB).a $(LIB).o

$(LIB).o: $(LIB).c
	gcc -c -Wall -m32 -fPIC $(LIB).c

list: lib$(LIB).a
	ar -t lib$(LIB).a

clean:
	rm -f $(LIB).o
	rm -f lib$(LIB).a
