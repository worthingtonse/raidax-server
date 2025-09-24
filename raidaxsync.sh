#!/bin/bash

dir=/root/raidax

chown -R root: /opt/raidax
data_dir=/opt/raidax/Data
chmod -R u=rwX,go=rX $data_dir

cd $dir
git pull -q

ts=$(git log -1 --format="%at" | xargs -I{} date -d @{} +%s)
bts=$(stat -c %Y /opt/raidax/raidax_server)

if [ $bts -lt $ts ]; then
	echo "MOD $ts $bts"
	make && make update
fi

