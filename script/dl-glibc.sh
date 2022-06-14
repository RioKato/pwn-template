#!/bin/sh

URL=ftp://ftp.gnu.org/gnu/glibc/

list(){
  curl -s "$URL" | awk '/glibc-[0-9]+\.[0-9]+(\.[0-9]+)?\.tar\.gz$/{print $9}' | sort -V
}

download(){
  curl -O "$URL""$1"
}

help(){
  echo "$0 [-l | -d libc]"
}


while getopts ld: OPT
do
  case $OPT in
    l) list
      exit 0
      ;;
    d) download $OPTARG
      exit 0
      ;;
  esac
done

help
