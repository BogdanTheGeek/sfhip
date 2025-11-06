bridge_setup :
	(sudo ip link add name br0 type bridge)||(true)
	(sudo ip link set dev br0 type brdige mcast_snooping 1)||(true)
	(sudo ip link set br0 up)||(true)
	sudo  ip link set tap1 up
	(sudo ip link set dev enx00e04c681031 master br0)||(true)
	sudo  ip link set dev tap1 master br0
	sudo  ip link set dev br0 up

bridge_teardown :
	(sudo ip link set tap1 down)||(true)
	(sudo ip addr flush dev eth0)||(true)
	(sudo ip link set br0 down)||(true)
	(sudo brctl delbr br0)||(true)


testbridge : linuxtest
	make bridge_setup
	sudo ./linuxtest tap1
	make bridge_teardown

