#!/bin/bash
 
filesystem="rootfs.cpio"
run="./run.sh"
extracted="./extracted"
 
extract_filesystem() {
  mkdir $extracted 
  cd $extracted 
  cpio -idv < "../$filesystem"
  cd ../
}
 
# extract filesystem if not exists
! [ -d "$extracted" ] && extract_filesystem
 
# compress
rm $filesystem 
chmod 777 -R $extracted
cd $extracted
find ./ -print0 | cpio --owner root --null -o -H newc > ../$filesystem
cd ../
 
# run
sh $run
