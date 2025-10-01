#!/bin/bash
#set -eu

BASEDIR=.

DEEPSYS=$1
CHISELS=$2
#TMPBASE=${4:-$(mktemp -d --tmpdir deepsys.XXXXXXXXXX)}
TMPBASE=.
TRACEDIR="${TMPBASE}/traces"
RESULTDIR="${TMPBASE}/results"
BASELINEDIR="${TMPBASE}/baseline"
BRANCH=$3

if [ ! -d "$TRACEDIR" ]; then
	mkdir -p $TRACEDIR
	cd $TRACEDIR
	wget https://s3.amazonaws.com/download.draios.com/sysdig-tests/traces.zip
	unzip traces.zip
	rm -rf traces.zip
	cd -
fi

if [ ! -d "$BASELINEDIR" ]; then
	mkdir -p $BASELINEDIR
	cd $BASELINEDIR
	wget -O baseline.zip https://s3.amazonaws.com/download.draios.com/sysdig-tests/baseline-$BRANCH.zip || wget -O baseline.zip https://s3.amazonaws.com/download.draios.com/sysdig-tests/baseline-dev.zip
	unzip baseline.zip
	rm -rf baseline.zip
	cd -
fi

echo "Executing deepsys tests in ${TMPBASE}"

ret=0

# Views to run
$BASEDIR/deepsys_batch_parser.sh $DEEPSYS $CHISELS "--raw -vprocs" $TRACEDIR $RESULTDIR/procs $BASELINEDIR/procs || ret=1
$BASEDIR/deepsys_batch_parser.sh $DEEPSYS $CHISELS "--raw -vfiles" $TRACEDIR $RESULTDIR/files $BASELINEDIR/files || ret=1
$BASEDIR/deepsys_batch_parser.sh $DEEPSYS $CHISELS "--raw -vconnections" $TRACEDIR $RESULTDIR/connections $BASELINEDIR/connections || ret=1
$BASEDIR/deepsys_batch_parser.sh $DEEPSYS $CHISELS "--raw -vcontainer_errors" $TRACEDIR $RESULTDIR/container_errors $BASELINEDIR/container_errors || ret=1
$BASEDIR/deepsys_batch_parser.sh $DEEPSYS $CHISELS "--raw -vcontainers" $TRACEDIR $RESULTDIR/containers $BASELINEDIR/containers || ret=1
$BASEDIR/deepsys_batch_parser.sh $DEEPSYS $CHISELS "--raw -vdirectories" $TRACEDIR $RESULTDIR/directories $BASELINEDIR/directories || ret=1
$BASEDIR/deepsys_batch_parser.sh $DEEPSYS $CHISELS "--raw -verrors" $TRACEDIR $RESULTDIR/errors $BASELINEDIR/errors || ret=1
$BASEDIR/deepsys_batch_parser.sh $DEEPSYS $CHISELS "--raw -vfile_opens" $TRACEDIR $RESULTDIR/file_opens $BASELINEDIR/file_opens || ret=1
$BASEDIR/deepsys_batch_parser.sh $DEEPSYS $CHISELS "--raw -vio_by_type" $TRACEDIR $RESULTDIR/io_by_type $BASELINEDIR/io_by_type || ret=1
$BASEDIR/deepsys_batch_parser.sh $DEEPSYS $CHISELS "--raw -vincoming_connections" $TRACEDIR $RESULTDIR/incoming_connections $BASELINEDIR/incoming_connections || ret=1
$BASEDIR/deepsys_batch_parser.sh $DEEPSYS $CHISELS "--raw -vincoming_connections" $TRACEDIR $RESULTDIR/incoming_connections $BASELINEDIR/incoming_connections || ret=1
$BASEDIR/deepsys_batch_parser.sh $DEEPSYS $CHISELS "--raw -vpage_faults" $TRACEDIR $RESULTDIR/page_faults $BASELINEDIR/page_faults || ret=1
$BASEDIR/deepsys_batch_parser.sh $DEEPSYS $CHISELS "--raw -vprocs_cpu" $TRACEDIR $RESULTDIR/procs_cpu $BASELINEDIR/procs_cpu || ret=1
$BASEDIR/deepsys_batch_parser.sh $DEEPSYS $CHISELS "--raw -vprocs_errors" $TRACEDIR $RESULTDIR/procs_errors $BASELINEDIR/procs_errors || ret=1
$BASEDIR/deepsys_batch_parser.sh $DEEPSYS $CHISELS "--raw -vprocs_fd_usage" $TRACEDIR $RESULTDIR/procs_fd_usage $BASELINEDIR/procs_fd_usage || ret=1
$BASEDIR/deepsys_batch_parser.sh $DEEPSYS $CHISELS "--raw -vsports" $TRACEDIR $RESULTDIR/sports $BASELINEDIR/sports || ret=1
$BASEDIR/deepsys_batch_parser.sh $DEEPSYS $CHISELS "--raw -vspy_syslog" $TRACEDIR $RESULTDIR/spy_syslog $BASELINEDIR/spy_syslog || ret=1
$BASEDIR/deepsys_batch_parser.sh $DEEPSYS $CHISELS "--raw -vspy_users" $TRACEDIR $RESULTDIR/spy_users $BASELINEDIR/spy_users || ret=1
$BASEDIR/deepsys_batch_parser.sh $DEEPSYS $CHISELS "--raw -vsyscalls" $TRACEDIR $RESULTDIR/syscalls $BASELINEDIR/syscalls || ret=1

#rm -rf "${TMPBASE}"
exit $ret
