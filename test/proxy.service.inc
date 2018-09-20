#!/bin/bash
#
# make script *.service, and call proxy.service.inc where first argument is URL, and second and third argument is passed from the parameters


shopt -s nocasematch

if [[ "$2" != "GET" && "$2" != "POST" && "$2" != "PUT" ]]; then
	echo "HTTP/1.0 405 Method not allowed";
	echo ""
	exit
fi
	

HDRS=("-H" "Connection: close")

function rdheaders() {
	
   POS=2

   read l
   while [[ "$l" != "" ]]; do
	if [[ "${l:0:5}" != "Host:" && "${l:0:11}" != "Connection:"  && "${l:0:8}" != "Upgrade:" ]] ; then
			HDRS[$POS]="-H"
			POS=$((POS + 1))
		   	HDRS[$POS]="$l"
			POS=$((POS + 1))
	fi
	read l

   done	

}

function processresponse() {

  read l
  while [[ "$l" != "" && "$l" != $'\r' ]] ; do
	if [[ "${l:0:18}" != "Transfer-Encoding:" ]] ; then
		echo $l	
	fi
	read l
  done
  echo
  cat

}

rdheaders

cat | curl -s -i -X $2 "${HDRS[@]}" -d @- "$1$3" | processresponse



