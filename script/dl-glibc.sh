#!/bin/sh

URL=ftp://ftp.gnu.org/gnu/glibc/

list(){
  curl -s "$URL" | awk '/glibc-[0-9]+\.[0-9]+(\.[0-9]+)?\.tar\.gz$/{print $9}' | sort -V
}

download(){
  curl -O "$URL""$1"
}

clone(){
  git clone https://sourceware.org/git/glibc.git
}

help(){
  echo "$0 [-c | -l | -d libc]"
}


while getopts ld:c OPT
do
  case $OPT in
    l) list
      exit 0
      ;;
    d) download $OPTARG
      exit 0
      ;;
    c) clone
      exit 0
      ;;
  esac
done

help
