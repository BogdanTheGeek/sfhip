all : linuxtest

SIZE_PREFIX:=riscv64-linux-gnu

size : linuxtest.c
	$(SIZE_PREFIX)-gcc -Os -g -o linuxtest.rv $^ -flto
	$(SIZE_PREFIX)-objdump -t linuxtest.rv | grep hip | grep -v sfhip_send_packet | tr -s ' ' | cut -f 4 -d' ' | cut -f 2 | sed -e 's/^0*//' | tr '[:lower:]' '[:upper:]' | sed -e 's/^/+/' | xargs echo "obase=10;ibase=16;0"  | bc | xargs echo "Total Size Bytes For hip Functions:"
	$(SIZE_PREFIX)-objdump -S linuxtest.rv > rv.lst

linuxtest : linuxtest.c
	$(PREFIX)-gcc -Os -g -o $@ $^ -flto
	$(SIZE_PREFIX)-objdump -t $@ | grep hip | grep -v sfhip_send_packet | tr -s ' ' | cut -f 4 -d' ' | cut -f 2 | sed -e 's/^0*//' | tr '[:lower:]' '[:upper:]' | sed -e 's/^/+/' | xargs echo "obase=10;ibase=16;0"  | bc | xargs echo "Total Size Bytes For hip Functions:"


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

