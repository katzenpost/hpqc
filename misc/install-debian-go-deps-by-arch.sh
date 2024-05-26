#!/bin/bash
set -e;

ARCH=$1;
# This BASE_PACKAGES list assumes a Docker image with golang installed
BASE_PACKAGES="ca-certificates clang git make";

if [ -n "$ARCH" ];
then
    if [ "$ARCH" == "386" ] || [ "$ARCH" == "i386" ] || [ "$ARCH" == "amd64" ];
    then
        dpkg --add-architecture i386;
        PACKAGES="$BASE_PACKAGES libc6-i386 libc6-dev linux-libc-dev linux-libc-dev:i386 libc6-dev-i386 libc6-i386-cross libc6 libc6-dev";
    fi

    if [ "$ARCH" == "arm" ] || [ "$ARCH" == "arm32v5" ] || [ "$ARCH" == "arm32v6" ] || [ "$ARCH" == "arm32v7" ];
    then
        PACKAGES="$BASE_PACKAGES libc6-armel-cross libc6-armhf-cross libc6-dev-armel-cross libc6-dev-armhf-cross";
    fi

    if [ "$ARCH" == "arm64" ];
    then
        PACKAGES="$BASE_PACKAGES libc6-arm64-cross libc6-dev-arm64-cross";
    fi

    if [ "$ARCH" == "mips" ];
    then
        PACKAGES="$BASE_PACKAGES libc6-dev-mips-cross linux-libc-dev-mips-cross";
    fi

    if [ "$ARCH" == "mipsle" ] || [ "$ARCH" == "mipsel" ];
    then
        PACKAGES="$BASE_PACKAGES libc6-dev-mipsel-cross linux-libc-dev-mipsel-cross";
    fi

    if [ "$ARCH" == "mips64" ];
    then
        PACKAGES="$BASE_PACKAGES libc6-dev-mips64-cross linux-libc-dev-mips64-cross";
    fi

    if [ "$ARCH" == "mips64le" ] || [ "$ARCH" == "mips64el" ];
    then
        PACKAGES="$BASE_PACKAGES libc6-dev-mipsn32-mips64el-cross linux-libc-dev-mips64el-cross";
    fi

    if [ "$ARCH" == "ppc64" ];
    then
        PACKAGES="$BASE_PACKAGES libc6-dev-powerpc-ppc64-cross libc6-dev-ppc64-cross linux-libc-dev-ppc64-cross ";
    fi

    if [ "$ARCH" == "ppc64le" ];
    then
        PACKAGES="$BASE_PACKAGES libc6-dev-ppc64el-cross linux-libc-dev-ppc64el-cross";
    fi

    if [ "$ARCH" == "riscv64" ];
    then
        PACKAGES="$BASE_PACKAGES libc6-dev-riscv64-cross";
    fi

    if [ "$ARCH" == "s390x" ];
    then
        PACKAGES="$BASE_PACKAGES libc6-dev-s390x-cross";
    fi
else
    echo "ARCH appears to be unset: ARCH=$ARCH";
    exit 1;
fi

apt update > /dev/null 2>&1;
echo "Installing required packages for $ARCH: $PACKAGES";
apt install -y --no-install-recommends $PACKAGES > /dev/null 2>&1;
echo "Required packages installed";
