# Description
A virtual kernel block driver that support encrypt/decrypt

# Usage
make && insmod lsblk.ko device_path="/dev/sda" # this will generate /dev/zspace_vdev


dd if=/dev/urandom bs=1M count=100 of=/dev/zspace_vdev # all data will be encrypted and wrote to /dev/sda
