all : linuxtest

linuxtest : linuxtest.c
	gcc -Os -g -o $@ $^ -flto
	objdump -t linuxtest | grep hip | tr -s ' ' | cut -f 4 -d' ' | cut -f 2 | sed -e 's/^0*//' | tr '[:lower:]' '[:upper:]' | sed -e 's/^/+/' | xargs echo "obase=10;ibase=16;0"  | bc | xargs echo "Total Size Bytes For hip Functions:"


testprom : linuxtest
	echo "Be sure to give tap1 an ip!"
	sudo ./linuxtest tap1 enx00249b462a68
#- enx00e04c681031

testlocal : linuxtest
	./linuxtest tap1 - 5 &
	ping 192.168.13.251 -c 2

# alternatively you just put your ethernet device after the -
# if you want to allow it out on your network.

clean :
	rm -rf linuxtest

