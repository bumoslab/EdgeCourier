# sudo ../../../rumprun/rumprun/rumprun/bin/rumprun xen -i -I newnet,xenif,'bridge=xenbr0,mac=00:16:3e:00:00:04' -W newnet,inet,dhcp \
#     -b python.iso,/python/lib/python3.5 \
#     -b Edge_1.0-dropbox.iso,/python/lib/python3.5/site-packages \
#     -e PYTHONHOME=/python -- python.bin -m main

# sudo ../../../rumprun/rumprun/rumprun/bin/rumprun xen -i -I newnet,xenif,'bridge=xenbr0,mac=00:16:3e:00:00:04' -W newnet,inet,dhcp \
# 	-b python.iso,/python/lib/python3.5 \
# 	-b Edge_1.0-onedrive.iso,/python/lib/python3.5/site-packages \
# 	-e PYTHONHOME=/python -- python.bin -m main

#sudo ../../../rumprun/rumprun/rumprun/bin/rumprun xen -i -I newnet,xenif,'bridge=virbr0,mac=00:16:3e:00:00:04' -W newnet,inet,static,192.168.122.2/24 \
#	-b python.iso,/python/lib/python3.5 \
#	-b test.iso,/python/lib/python3.5/site-packages \
#	-e PYTHONHOME=/python -- python.bin -m main

#sudo ../../../rumprun/rumprun/rumprun/bin/rumprun xen -i -I newnet,xenif,'bridge=virbr0,mac=00:16:3e:00:00:04' -W newnet,inet,dhcp \
#	-b python.iso,/python/lib/python3.5 \
#	-b diff_patch.iso \
#	-b dropbox.iso \
#	-b main.iso,/python/lib/python3.5/site-packages \
#	-e PYTHONHOME=/python -- python.bin -m main
	

# sudo ../../../rumprun/rumprun/rumprun/bin/rumprun xen -i -I newnet,xenif,'bridge=virbr0,mac=00:16:3e:00:00:04' -W newnet,inet,dhcp \
#	-b python.iso,/python/lib/python3.5 \
#   	-b diff_patch.iso ,/python/lib/python3.5/site-packages/diff_match_patch \
#	-b dropbox.iso,/python/lib/python3.5/site-packages/dropbox \
#	-b main.iso,/python/lib/python3.5/site-packages \
#	-e PYTHONHOME=/python -- python.bin -m main

help () {
	echo "This is the utility for helping create multiple unikernel instances \n \
		./command.sh instances_amount \n "
}

CreateUnikernel () {
	echo $1 $2 $3
    sudo ../../../rumprun/rumprun/rumprun/bin/rumprun xen -i -I newnet,xenif,'bridge=xenbr0,mac=00:16:3e:00:00:04' -W newnet,inet,dhcp \
	       -b python.iso,/python/lib/python3.5 \
	       -b $2,/python/lib/python3.5/site-packages \
	       -e PYTHONHOME=/python -- $1 -m main $3 $4 
}

CreateMultiple () {
	echo "Starting create mutiple unikernels ... Amount: $1"
	for i in $(seq 1 1 $1) 
	do
		cp python.bin python-$i.bin
	done
}

RemoveTempBinary () {
	echo "Removing all binary files "
	for entry in "$PWD"/*
	do
		filename=`basename $entry`
		if [[ $filename == python-*.bin ]]; then
			`rm $filename`
		fi
	done


}

[ ! $# -eq 1 ] && help && exit 0
echo $1
# CreateUnikernel $1 $2 $3
CreateMultiple $1
RemoveTempBinary
