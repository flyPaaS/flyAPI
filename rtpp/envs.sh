#!/bin/bash
RTPP_APP_DIR=${PWD}
COMM_DIR=${RTPP_APP_DIR}/../../common
APP_COMM_DIR=${RTPP_APP_DIR}/../common
MODULE_DIR=${RTPP_APP_DIR}/modules
export RTPP_APP_DIR
export COMM_DIR
export APP_COMM_DIR
export MODULE_DIR

KERNEL_VER=`uname -r`
export KERNEL_VER
export PRODUCT=RTPP


CENTOS_VER=`sed -n 1p /etc/issue | awk -F ' ' '{print $4}'`
if [ $CENTOS_VER = '(Final)' ]; then
        CENTOS_VER=`sed -n 1p /etc/issue | awk -F ' ' '{print $3}'`
fi
export CENTOS_VER
