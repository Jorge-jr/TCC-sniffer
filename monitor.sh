#! /bin/sh.

sudo iw phy phy0 interface add mon0 type monitor
sudo ifconfig mon0 up
sudo ip link show dev mon0
