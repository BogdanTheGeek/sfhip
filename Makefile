all : linuxtest

linuxtest : linuxtest.c
	gcc -O1 -g -o $@ $^

testprom : linuxtest
	sudo ./linuxtest tap1 enx00e04c681031

clean :
	rm -rf linuxtest

