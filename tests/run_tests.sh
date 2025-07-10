#!/bin/bash
set -vmeE
ulimit -c unlimited

DPIP_PROC=0
ECHOS_PROC=0

# Must run as root
[ $(id -u) -eq 0 ] || exit 1

trap 'end $?' EXIT
end() {
    sleep 1
    chmod a+rw temp temp/*
    ip netns delete dpip_test_suite
    [ $DPIP_PROC -eq 0 ] || kill $DPIP_PROC
    [ $ECHOS_PROC -eq 0 ] || kill $ECHOS_PROC
    [ $1 -eq 0 ] && echo -e "\nTests OK!\n"
    exit $1
}

trap 'err $? $LINENO' ERR
err() {
    echo "Tests failed: error $1 occurred at line $2"
    exit $1
}


# setup env
cd "$(dirname "$0")"
mkdir -p temp
rm -rf temp/*

mapfile -t nss < <(ip netns list)
if [[ " ${nss[@]} " =~ " dpip_test_suite " ]]; then
	ip netns delete dpip_test_suite
fi
ip netns add dpip_test_suite

client1_ip4=10.123.0.2
client2_ip4=10.123.0.3
client1_ip6=fc00:1::2
client2_ip6=fc00:1::3

export DPIP_IP4_ADDR=10.123.0.1
export DPIP_IP4_MASK=255.255.255.0
export DPIP_IP4_GW=10.123.0.2
export DPIP_IP6_ADDR=fc00:1::1
export HTTP_PORT=80
export TCP_ECHO_PORT=6060
export TCP_PROXY_PORT=6767
export TCP_PROXY_TARGET=$client2_ip4
export TCP_PROXY_TARGET_PORT=7070

eal_params='-l 2 --vdev=net_tap0,iface=dpip0 --no-pci --no-huge --log-level=*.*:debug --log-timestamp --'
../dpip_app $eal_params &> temp/dpip_app.log &
DPIP_PROC=$!

sleep 2

#MAC address
ip link set dev dpip0 address 72:d2:12:44:24:84

ip link set dpip0 netns dpip_test_suite up

ip -n dpip_test_suite addr add dev dpip0 ${client1_ip4}/24
ip -n dpip_test_suite addr add dev dpip0 ${client2_ip4}/24
ip -n dpip_test_suite -6 addr add dev dpip0 ${client1_ip6}/64
ip -n dpip_test_suite -6 addr add dev dpip0 ${client2_ip6}/64

ip netns exec dpip_test_suite ip addr show
ip netns exec dpip_test_suite ip route
ip netns exec dpip_test_suite ip -6 route

ip netns exec dpip_test_suite python3 echo_server.py --tcp --address $TCP_PROXY_TARGET &> temp/echo_server.log &
ECHOS_PROC=$!

# dpdk-dumpcap -w temp/dumpcap.pcapng &> /dev/null &
ip netns exec dpip_test_suite tcpdump -i dpip0 -w temp/tcpdump.pcapng &>/dev/null &

sleep 3

# test ping
time ip netns exec dpip_test_suite ping -I $client1_ip4 -w 15 -c1 $DPIP_IP4_ADDR
time ip netns exec dpip_test_suite ping -I $client2_ip4 -w 15 -c1 $DPIP_IP4_ADDR

time ip netns exec dpip_test_suite ping -I $client1_ip6 -w 15 -c1 $DPIP_IP6_ADDR
time ip netns exec dpip_test_suite ping -I $client2_ip6 -w 15 -c1 $DPIP_IP6_ADDR

# test echo
ip netns exec dpip_test_suite python3 echo_client.py &> temp/echo_client.log

# test http
url="http://$DPIP_IP4_ADDR/"
url6="http://[$DPIP_IP6_ADDR]/"
curl="ip netns exec dpip_test_suite curl -km 200 -o /dev/null"

time $curl --interface $client1_ip4 $url
time $curl --interface $client1_ip4 ${url}close

time $curl --interface $client2_ip4 $url
time $curl --interface $client2_ip4 ${url}close

time $curl --interface $client1_ip6 $url6
time $curl --interface $client1_ip6 ${url6}close

time $curl --interface $client2_ip6 $url6
time $curl --interface $client2_ip6 ${url6}close

[ $(pidof dpip_app) -eq $DPIP_PROC ] || exit 1
ps -Llp $DPIP_PROC

