#! /bin/sh

# Startup script to create the device-mapper control device 
# on non-devfs systems.
# Non-zero exit status indicates failure.

# These correspond to the definitions in device-mapper.h and dm.h
DM_DIR="device-mapper"
DM_NAME="device-mapper"

set -e

dir="/dev/$DM_DIR"
control="$dir/control"

# Check for devfs, procfs
if test -e /dev/.devfsd ; then
	echo "devfs is in use, no need to create devices."
	exit
fi

if test ! -e /proc/devices ; then
	echo "procfs is not being used; you'll have to make $control manually."
	exit
fi

# Get major, minor, and mknod
major=$(awk '$2 ~ /^misc$/ {print $1}' /proc/devices)
minor=$(awk "\$2 ~ /^$DM_NAME\$/ {print \$1}" /proc/misc)

if test -z "$major" -o -z "$minor" ; then
	echo "$DM_NAME kernel module isn't loaded; refusing to create $control."
	exit
fi

mkdir -p --mode=755 $dir
test -e $control && rm -f $control

echo "Creating $control character device with major:$major minor:$minor."
mknod --mode=600 $control c $major $minor

