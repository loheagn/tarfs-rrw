#!/bin/bash

# 设置OverlayFS所需的目录名称
lower_dir="/mnt/t1"
upper_dir="/tmp/overlay/upper"
work_dir="/tmp/overlay/work"
merged_dir="/tmp/overlay/merged"

# 创建必要的目录
mkdir -p "$upper_dir" "$work_dir" "$merged_dir"

# 检查OverlayFS支持
if ! grep -q overlay /proc/filesystems; then
    echo "The overlay filesystem is not supported in this system."
    exit 1
fi

# 挂载OverlayFS
mount -t overlay overlay -o lowerdir="$lower_dir",upperdir="$upper_dir",workdir="$work_dir" "$merged_dir"

# 检查挂载是否成功
if mountpoint -q "$merged_dir"; then
    echo "OverlayFS mounted successfully at $merged_dir"
else
    echo "Failed to mount OverlayFS"
    exit 1
fi

echo "You can now access the overlay filesystem at $merged_dir"