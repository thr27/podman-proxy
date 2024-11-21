#!/bin/bash
set -m
source `dirname $0`/../lib/bash_lib.sh
SCRIPT=`readlink -f -- $0`
SCRIPTPATH=`dirname $SCRIPT`
echo -e "\n ------------------------------------------------------------"
echo $0
date

export SSH_CONFIG_PODMAN_PROXY="$HOME/.ssh/config_podman_proxy"
export SSH_PODMAN_PROXY_PID="$HOME/.ssh/ssh_podman_proxy.pid"
export SSH_CONFIG_PREV_SHA1=""

SSH_PROXY_PID=""
MONITOR_PID=""

[ -f $SSH_PODMAN_PROXY_PID ] && rm $SSH_PODMAN_PROXY_PID
SSH_PODMAN_PROXY_LOCKFILE="/tmp/ssh_podman_proxy.$$.lck"
PODMAN_PROXY_RESTART_SGINAL="/tmp/podman_proxy.$$.evnt"

SCRIPT_LOCKFILE="/tmp/podman_proxy.lck"

# Only allow to run once
if [ -e "$SCRIPT_LOCKFILE" ]; then
	MONITOR_PID=$(cat "$SCRIPT_LOCKFILE")
	if [ ! -z "$MONITOR_PID" ]; then
		if ps -p $MONITOR_PID > /dev/null; then
			## monitor is still running
			sleep 2
			if ok "Monitor is already running. Restart anyway? ($SCRIPT_LOCKFILE)"; then 
				rm $SCRIPT_LOCKFILE
				kill -9 $MONITOR_PID
			else
				sleep 2
				exit 1
			fi
		else
			rm $SCRIPT_LOCKFILE
		fi
	else
		rm $SCRIPT_LOCKFILE
	fi
fi
echo $$ > $SCRIPT_LOCKFILE

function cleanup() {
	kill_proxy_ssh_daemon
	[ -z $MONITOR_PID ] && kill $MONITOR_PID
	[ -f $SSH_PODMAN_PROXY_LOCKFILE ] && rm $SSH_PODMAN_PROXY_LOCKFILE
	[ -f $SCRIPT_LOCKFILE ] && rm $SCRIPT_LOCKFILE
	[ -f $PODMAN_PROXY_RESTART_SGINAL ] && rm $PODMAN_PROXY_RESTART_SGINAL
}
trap cleanup EXIT

function find_podman_root_socket() {
	echo ${FUNCNAME[0]}
	export PODMAN_SOCKET=$(podman system connection list --format='{{.Name}}|{{.URI}}'|grep "default-root"|cut -d '|' -f 2)
	export PODMAN_HOST=$(echo $PODMAN_SOCKET| sed -n 's|ssh://\([^:]*\):.*|\1|p'| sed 's/\(.*\)@\([^ ]*\)/\2/')
	export PODMAN_USER=$(echo $PODMAN_SOCKET| sed -n 's|ssh://\([^:]*\):.*|\1|p'| sed 's/\(.*\)@\([^ ]*\)/\1/')
	export PODMAN_PORT=$(echo $PODMAN_SOCKET| sed -n 's/.*:\([0-9]*\).*/\1/p')
	export PODMAN_IDENT=$(podman system connection list --format='{{.Name}}|{{.Identity}}'|grep "default-root"|cut -d '|' -f 2)
}
function find_running_containers() {
	echo ${FUNCNAME[0]}
	export CONTAINERS=$(podman ps --format '{{.ID}}'|grep -v 'CONTAINER')
}
function get_local_forward() {
	echo ${FUNCNAME[0]}
	LOCAL_FORWARD=""

	for container in $CONTAINERS; do
		echo "## container: ${container}"	
		PORT_MAPPINGS=$(podman inspect $container --format='{{ range  $value := .HostConfig.PortBindings }}{{ json $value }} {{end}}'|sed 's@},{@ @g')
		LOCAL_FORWARD=$(cat <<EOF
		$LOCAL_FORWARD
		## -- conatiner: ${container}
EOF
)
		for mapping in $PORT_MAPPINGS; do
			echo "## port mapping: ${mapping}"
			HostIp=$(echo ${mapping} | sed -n 's/.*"HostIp":"\([^"]*\)".*"HostPort":"\([^"]*\)".*/\1/p')
			HostPort=$(echo ${mapping} | sed -n 's/.*"HostIp":"\([^"]*\)".*"HostPort":"\([^"]*\)".*/\2/p')
			LOCAL_FORWARD=$(cat <<EOF
		$LOCAL_FORWARD
		LocalForward $HostIp:$HostPort $HostIp:$HostPort
EOF
)
		done
		
	done
	export LOCAL_FORWARD
}
function define_ssh_config_var() {
	echo ${FUNCNAME[0]}
	export SSH_CONFIG=$(cat <<EOF

Host podman-proxy-ssh
	User root
    IdentitiesOnly=yes
	StrictHostKeyChecking no
	UserKnownHostsFile=/dev/null
	 
	HostName $PODMAN_HOST
	Port $PODMAN_PORT

	IdentityFile $PODMAN_IDENT
	$LOCAL_FORWARD

EOF
	)
}

function start_proxy_ssh() {
	echo ${FUNCNAME[0]}

	/usr/bin/ssh -N -T -F $SSH_CONFIG_PODMAN_PROXY podman-proxy-ssh &
	export SSH_PROXY_PID=$!
	echo $SSH_PROXY_PID > $SSH_PODMAN_PROXY_PID
}
function start_proxy_ssh_daemon() {
	echo ${FUNCNAME[0]}

	[ -f $SSH_PODMAN_PROXY_PID ] && rm $SSH_PODMAN_PROXY_PID

	find_running_containers
	echo "## running containers: ${CONTAINERS}"

	get_local_forward
	echo "## local forward: ${LOCAL_FORWARD}"

	define_ssh_config_var

	echo "## ssh config: ${SSH_CONFIG}"

	SSH_CONFIG_SHA1=$(echo "${SSH_CONFIG}"| sha1sum | cut -d' ' -f 1)

	if [ "$SSH_CONFIG_PREV_SHA1" != "$SSH_CONFIG_SHA1" ]; then

		echo "${SSH_CONFIG}" > ${SSH_CONFIG_PODMAN_PROXY}
		SSH_CONFIG_PREV_SHA1=$(cat $SSH_CONFIG_PODMAN_PROXY| sha1sum | cut -d ' ' -f 1)
		echo "## ssh config sha1: $SSH_CONFIG_PREV_SHA1 != $SSH_CONFIG_SHA1"
		
		start_proxy_ssh 

		echo "## SSH_PROXY_PID $SSH_PROXY_PID"
	fi
}
function is_restart_signal_received() {
	echo ${FUNCNAME[0]}

	if [ -f $PODMAN_PROXY_RESTART_SGINAL ]; then 
		rm $PODMAN_PROXY_RESTART_SGINAL
		restart_ssh_proxy
	fi
}
function is_mapping_complete() {
	echo ${FUNCNAME[0]}

	find_running_containers

	for container in $CONTAINERS; do
		if ! grep -q "$container" "$SSH_CONFIG_PODMAN_PROXY"; then
			kill_proxy_ssh_daemon
			break
		fi
	done
}
function is_ssh_daemon_alive() {
	echo ${FUNCNAME[0]}

	if [ -f $SSH_PODMAN_PROXY_LOCKFILE ]; then
		echo "## ssh-proxy is about to be restarted. Exiting."
		return
	fi

	if [ -f $SSH_PODMAN_PROXY_PID ]; then
		SSH_PROXY_PID=$(cat "$SSH_PODMAN_PROXY_PID")
		if [ ! -z "$SSH_PROXY_PID" ]; then
			if ps -p $SSH_PROXY_PID > /dev/null; then
				## ok, ssh proxy is still running
				sleep 2
				## echo "## ssh child process with PID $SSH_PROXY_PID is still running..."
			else
				rm $SSH_PODMAN_PROXY_PID
				restart_ssh_proxy
			fi
		fi
	fi
}
function kill_proxy_ssh_daemon() {
	echo ${FUNCNAME[0]}
	[ -f $SSH_PODMAN_PROXY_PID ] && SSH_PROXY_PID=$(cat "$SSH_PODMAN_PROXY_PID")
	if [ ! -z "$SSH_PROXY_PID" ]; then
		if ps -p $SSH_PROXY_PID > /dev/null; then
			echo "## ssh child process with PID $SSH_PROXY_PID is still running... killing"
			kill -9 $SSH_PROXY_PID
		else
			echo "## ssh child process with PID $SSH_PROXY_PID has already died..."
		fi
	fi
}
function restart_ssh_proxy() {
	echo ${FUNCNAME[0]}
	touch $SSH_PODMAN_PROXY_LOCKFILE

	kill_proxy_ssh_daemon
	start_proxy_ssh_daemon

	rm $SSH_PODMAN_PROXY_LOCKFILE
}
function signal_restart_ssh_proxy() {
	echo ${FUNCNAME[0]}
	touch $PODMAN_PROXY_RESTART_SGINAL
}
function monitor_podman_start_stop_events() {
	echo ${FUNCNAME[0]}
	# Continuously read the output of podman events and filter for specific keywords
	podman events -f "event=start" -f "event=died" --format="{{ .TimeNano }}|{{ .ID }}|{{ .Status }}"| while read -r line; do
		echo "## Filtered event: $line"
		
		signal_restart_ssh_proxy
	done
}
function main() {
	echo ${FUNCNAME[0]}

	find_podman_root_socket

	echo "## podman socket: ${PODMAN_SOCKET}"
	echo "## podman host: ${PODMAN_HOST}"
	echo "## podman user: ${PODMAN_USER}"
	echo "## podman port: ${PODMAN_PORT}"
	echo "## podman identity: ${PODMAN_IDENT}"

	if [ -z "$SSH_PROXY_PID" ]; then
		restart_ssh_proxy
	fi
	# monitor_podman_start_stop_events &
	#export MONITOR_PID=$!

	echo "## ssh-proxy started as $SSH_PROXY_PID"
	echo "## monitor PID: $$ sleeping..."
	while true; do
		sleep 10
		is_ssh_daemon_alive # check if ssh-proxy is still running
		is_restart_signal_received # check if restart signal has been received
		is_mapping_complete
	done
}
main