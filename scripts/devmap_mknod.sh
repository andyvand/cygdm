#! /bin/sh

# Startup script to create the device-mapper control device 
# on non-devfs systems.
# Non-zero exit status indicates failure.

# These correspond to the definitions in device-mapper.h and dm.h
DM_DIR="device-mapper"
DM_NAME="device-mapper"

set -e

make_dir()
{
    [ -d $dir ] || mkdir --mode=755 $dir
}

make_node()
{
    rm -f $control || true
    echo Creating $control character device with major:$major minor:$minor
    mknod --mode=600 $control c $major $minor
}

dir="/dev/$DM_DIR"
control="$dir/control"
devfs=$(grep -c '\<devfs' /proc/filesystems || true)

if [ $devfs -eq 1 ]; then
    exit;
fi

make_dir

major=$(awk '$2 ~ /^misc$/ {print $1}' /proc/devices)
minor=$(awk "\$2 ~ /^$DM_NAME\$/ {print \$1}" /proc/misc)

make_node

