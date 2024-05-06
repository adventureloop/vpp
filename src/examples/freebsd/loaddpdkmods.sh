#!/bin/sh
#
# This example configures the contigmem kernel module for use with dpdk. It
# works with the update contigmem kernel module with multiple device support.
#
# The module is available from this dpdk commit in my development tree:
# https://github.com/adventureloop/dpdk/commit/3342a79d56c987dacb290801defdc7c2d54f936e
#

dpdkpath="$(HOME)/code/dpdk"	# this is only correct on my systems

kenv hw.contigmem.num_devices=2
kenv hw.contigmem.num_buffers=2
kenv hw.contigmem.buffer_size=536870912

kenv hw.nic_uio.bdfs="0:3:0,0:4:0"

cd $dpdkpath

make -C contigmem
make -C nic_uio

kldload ./contigmem/contigmem.ko
kldload ./nic_uio/nic_uio.ko
