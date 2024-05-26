#!/bin/bash
#
# Test cross compile of golang module using clang
# This is meant to be called as part of `.woodpecker/golang.yml`
#
set -e;

export ARCH=$1;
export ARCH_ALT=$ARCH;
export GOOS=linux;
export CGO_ENABLED=1;
export HOST_ARCH=`uname -m`;
export PLATFORM=$ARCH;
export PLATFORM_SIZE=64;
export CGO_CFLAGS_ALLOW="";
export GOARCH=$ARCH;
export EXTRA_FLAGS="";
export EXTRA_INCLUDE="-I /usr/$ARCH_ALT-linux-gnu/include/";
export TARGET="--target=$PLATFORM-pc-linux-gnu";
export SUBARCHES="none";
CHECKMARK="\xE2\x9C\x94";

if [ -n "$ARCH" ];
then

    if [ "$ARCH" == "arm64" ];
    then
        export GOARCH=arm64;
        export PLATFORM=arm64;
        export ARCH_ALT=aarch64;
        export PLATFORM_SIZE=64; # Default with overrides below
        export EXTRA_INCLUDE="-I /usr/$ARCH_ALT-linux-gnu/include/";
        export SUBARCHES="none";
        export TARGET="--target=$PLATFORM-pc-linux-gnu";
    fi

    if [ "$ARCH" == "arm32v5" ];
    then
        export ARCH_ALT=arm-linux-gnueabihf;
        export CGO_CFLAGS_ALLOW="-fforce-enable-int128";
        export EXTRA_FLAGS="-fforce-enable-int128 -mfloat-abi=hard";
        export EXTRA_INCLUDE="-I /usr/$ARCH_ALT/include/";
        export GOARCH=arm;
        export GOARM=5;
        export PLATFORM=arm32v5;
        export PLATFORM_SIZE=32;
        export SUBARCHES="5";
        export TARGET="--target=arm-pc-linux-gnu";
    fi

    if [ "$ARCH" == "arm32v6" ];
    then
        export ARCH_ALT=arm-linux-gnueabi;
        export CGO_CFLAGS_ALLOW="-fforce-enable-int128";
        export EXTRA_FLAGS="-fforce-enable-int128 -mfloat-abi=soft";
        export EXTRA_INCLUDE="-I /usr/$ARCH_ALT/include/";
        export GOARCH=arm;
        export GOARM=6;
        export PLATFORM=arm32v6;
        export PLATFORM_SIZE=32;
        export SUBARCHES="6";
        export TARGET="--target=arm-pc-linux-gnu";
    fi

    if [ "$ARCH" == "arm32v7" ] || [ "$ARCH" == "arm" ];
    then
        export ARCH_ALT=arm-linux-gnueabi;
        export CGO_CFLAGS_ALLOW="-fforce-enable-int128";
        export EXTRA_FLAGS="-fforce-enable-int128 -mfloat-abi=soft";
        export EXTRA_INCLUDE="-I /usr/$ARCH_ALT/include/";
        export GOARCH=arm;
        export GOARM=7;
        export PLATFORM=arm32v7;
        export PLATFORM_SIZE=32;
        export SUBARCHES="7";
        export TARGET="--target=arm-pc-linux-gnu";
    fi

    if [ "$ARCH" == "i386" ] || [ "$ARCH" == "386" ] || [ "$ARCH" == "i686" ];
    then
        export ARCH=386;
        export ARCH_ALT=i686;
        export PLATFORM=i386;
        export PLATFORM_SIZE=32;
        export CGO_CFLAGS_ALLOW="-fforce-enable-int128";
        export GOARCH=$ARCH;
        export EXTRA_FLAGS="-fforce-enable-int128";
        export TARGET="--target=$PLATFORM-pc-linux-gnu";
        export EXTRA_INCLUDE="-I /usr/$ARCH_ALT-linux-gnu/include/";
        export SUBARCHES="none";
    fi

    if [ "$ARCH" == "mips" ];
    then
        export CGO_CFLAGS_ALLOW="-fforce-enable-int128";
        export EXTRA_FLAGS="-fforce-enable-int128";
        export PLATFORM_SIZE=32;
        export TARGET="--target=$PLATFORM-pc-linux-gnu";
        export EXTRA_INCLUDE="-I /usr/$ARCH_ALT-linux-gnu/include/";
    fi

    if [ "$ARCH" == "mipsle" ] || [ "$ARCH" == "mipsel" ];
    then
        export GOARCH=mipsle;
        export PLATFORM=mipsle;
        export PLATFORM_SIZE=32;
        export CGO_CFLAGS_ALLOW="-fforce-enable-int128";
        export EXTRA_FLAGS="-fforce-enable-int128";
        export EXTRA_INCLUDE="-I /usr/mipsel-linux-gnu/include/";
        export TARGET="--target=mipsel-pc-linux-gnu";
    fi

    if [ "$ARCH" == "mips64" ];
    then
        export TARGET="--target=$PLATFORM-pc-linux-gnu";
        export EXTRA_INCLUDE="-I /usr/$ARCH_ALT-linux-gnuabi64/include/";
    fi

    if [ "$ARCH" == "mips64le" ] || [ "$ARCH" == "mips64el" ];
    then
        export GOARCH=mips64le;
        export PLATFORM=mips64el;
        export TARGET="--target=$PLATFORM-pc-linux-gnu";
        export EXTRA_INCLUDE="-I /usr/mips64el-linux-gnuabi64/include/";
    fi


    if [ "$ARCH" == "riscv64" ];
    then
        export PLATFORM=riscv64;
        export EXTRA_INCLUDE="-I /usr/$ARCH_ALT-linux-gnu/include/";
    fi

    if [ "$ARCH" == "ppc64" ];
    then
        export GOARCH=ppc64;
        export PLATFORM=ppc64;
        export ARCH_ALT=powerpc64-linux-gnu;
        export EXTRA_INCLUDE="-I /usr/$ARCH_ALT/include/";
    fi

    if [ "$ARCH" == "ppc64le" ];
    then
        export GOARCH=ppc64le;
        export PLATFORM=ppc64le;
        export ARCH_ALT=powerpc64le-linux-gnu;
        export EXTRA_INCLUDE="-I /usr/$ARCH_ALT/include/";
    fi

    if [ "$ARCH" == "s390x" ];
    then
        export EXTRA_FLAGS="-fforce-enable-int128";
        export TARGET="--target=$PLATFORM-pc-linux-gnu";
        export EXTRA_INCLUDE="-I /usr/$ARCH_ALT-linux-gnu/include/";
        export SUBARCHES="none";
    fi

        if [ -n "$GOARCH" ];
        then
            export GOARCH=$ARCH;
        fi

        for SUBARCH in $SUBARCHES
        do
           if [ "$ARCH" == "arm32v5" ] || [ "$ARCH" == "arm32v6" ] \
                                       || [ "$ARCH" == "arm32v7" ] \
                                       || [ "$ARCH" == "arm" ];
           then
               export GOARCH=arm;
               export GOARM=$SUBARCH;
               echo -n "$GOARCH/$GOARM $BITS bits:";
           else
               echo -n "$GOARCH $BITS bits:";
           fi

	   cd server/cmd/server;
           CC="clang $TARGET $EXTRA_FLAGS $EXTRA_INCLUDE" \
             go build;
	   cd ../../..;
	   echo -e "$CHECKMARK";

	   cd authority/cmd/voting;
           CC="clang $TARGET $EXTRA_FLAGS $EXTRA_INCLUDE" \
             go build;
	   cd ../../..;
	   echo -e "$CHECKMARK";
	   
        done


    if [ "$ARCH" == "amd64" ];
    then
        echo "Running tests on $HOST_ARCH";
 
            export GOARCH=amd64;
            echo "$GOARCH $BITS bits:";
            CC="clang $TARGET $EXTRA_FLAGS $EXTRA_INCLUDE" \
                go test -v ./...
            echo -n "$GOARCH $BITS bits:";
            echo -e "$CHECKMARK";
     fi

    exit $?;
fi
