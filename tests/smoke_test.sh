#!/bin/bash
# Cyanide Honeypot Mega Smoke Test Script
# This script covers most categories of emulated commands.

echo "--- 1. Navigation and FS ---"
pwd
mkdir -p /tmp/smoke_test
cd /tmp/smoke_test
touch file1.txt
echo "cyanide test" > file2.txt
cp file2.txt file3.txt
mv file3.txt file4.txt
ls -la
rm file1.txt

echo "--- 2. Content processing ---"
cat file2.txt | grep cyanide
echo -e "line1\nline2\nline3" > lines.txt
head -n 1 lines.txt
tail -n 1 lines.txt
awk '{print $1}' file2.txt

echo "--- 3. System Info ---"
id
whoami
uptime
uname -a
free -m
df -h
ps aux
date

echo "--- 4. Networking ---"
ifconfig
ip addr
netstat -ant
ss -l
ping -c 1 8.8.8.8
curl -I http://google.com
wget -q -O - http://example.com

echo "--- 5. Admin & Packages ---"
chmod 777 file4.txt
sudo whoami
doas id
apt-get update
dpkg -l
yum update
rpm -qa

echo "--- 6. Development Tools ---"
python3 --version
perl -e 'print "hello"'
echo "int main(){return 0;}" > test.c
gcc test.c -o test_bin
make --version

echo "--- 7. Misc ---"
history
crontab -l

echo "--- SMOKE TEST COMPLETE ---"
