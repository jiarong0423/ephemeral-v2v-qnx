#!/bin/sh
# j24b_boot.sh - J24B Candidate C: executed from IFS (/proc/boot/j24b_boot.sh) BEFORE startup.sh
# (before io-sock networking, sshd, and planner). Uses ksh builtins only (no /system/bin yet).
echo "0123456789abcdef0123456789abcdef" > /dev/shmem/j24b_g.key
echo "0123456789abcdef0123456789abcdef" > /dev/shmem/j24b_a.key
echo "fedcba9876543210fedcba9876543210" > /dev/shmem/j24b_f.key
if [ -f /proc/boot/secpol.bin ] || [ -f /proc/boot/build/secpol.bin ]; then
  /proc/boot/on -T j23b_gate_t /proc/boot/v2v-j23b gate --key /dev/shmem/j24b_g.key --fkey /dev/shmem/j24b_f.key --veh 1 --map 0 --log /dev/shmem/j24b_gate.log --ident uid --no-comm --j24-prio 66 --tick-prio 66 &
else
  /proc/boot/v2v-j23b gate --key /dev/shmem/j24b_g.key --fkey /dev/shmem/j24b_f.key --veh 1 --map 0 --log /dev/shmem/j24b_gate.log --ident uid --no-comm --j24-prio 66 --tick-prio 66 &
fi
GP=$!
echo "$GP" > /dev/shmem/j24b_gate.pid
waitfor /dev/name/local/j23b_gate 5
echo "[J24B-BOOT] gate READY pid=${GP} prio=66"
if [ -f /proc/boot/secpol.bin ] || [ -f /proc/boot/build/secpol.bin ]; then
  /proc/boot/on -T j23b_act_t /proc/boot/v2v-j23b act --dir /dev/shmem --key /dev/shmem/j24b_a.key --veh 1 --map 0 --x0 -600 --log /dev/shmem/j24b_act.log --j24-prio 65 &
else
  /proc/boot/v2v-j23b act --dir /dev/shmem --key /dev/shmem/j24b_a.key --veh 1 --map 0 --x0 -600 --log /dev/shmem/j24b_act.log --j24-prio 65 &
fi
AP=$!
echo "$AP" > /dev/shmem/j24b_act.pid
sleep 1
echo "[J24B-BOOT] act READY safe_state=hold pid=${AP} prio=65"
