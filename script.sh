IP_ADDRESS=10.0.0.1/24

gcc -O3 -Wall -Wextra -o firewall firewall.c -lpcap

sudo ./firewall -i tun0 -f rules.txt &

sleep 1

sudo ip link set tun0 up
sudo ip addr add $IP_ADDRESS dev tun0

echo "Firewall rodando em tun0 com IP: $IP_ADDRESS"