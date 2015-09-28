PROG=encrypt


all: $(PROG)

$(PROG): $(PROG).c
	gcc -m32 $(PROG).c -fno-stack-protector -z execstack -ggdb -o $(PROG) \
		-I../TEA -L../TEA -lTEA

run: $(PROG)
	./$(PROG)

debug: $(PROG)
	gdb -q ./$(PROG)

clean:
	rm -f $(PROG)
