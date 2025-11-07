all : linuxtest

linuxtest : linuxtest.c
	gcc -O1 -g -o $@ $^

testprom : linuxtest
	echo "Be sure to give tap1 an ip!"
	sudo ./linuxtest tap1 enx00e04c681031

testlocal : linuxtest
	./linuxtest tap1 - 4 &
	ping 192.168.13.251 -c 2

# alternatively you just put your ethernet device after the -
# if you want to allow it out on your network.

clean :
	rm -rf linuxtest

