#!/sbin/runscript
# Copyright 1999-2011 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: /var/cvsroot/gentoo-x86/app-admin/sysstat/files/sysstat.init.d,v 1.3 2011/05/18 02:21:33 jer Exp $

CHSYSPASS_PID=/var/run/chsyspass.pid

depend() {
    need net
    after sshd
}

start() {
    ebegin "Starting Chilli Systems password service on port 5000"
    start-stop-daemon --start --quiet --exec /usr/bin/chillisys-pass-web --pidfile "${CHSYSPASS_PID}"
    eend $?
}

stop() {
    ebegin "Stoping Chilli Systems password service on port 5000"
    start-stop-daemon --stop --quiet --pidfile "${CHSYSPASS_PID}"
    eend $?
}