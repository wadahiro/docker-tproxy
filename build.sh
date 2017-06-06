#!/bin/sh

DIR=$(cd $(dirname $0); pwd)
BUILD_DIR=$DIR/bin
GOPATH=$BUILD_DIR
go get github.com/cybozu-go/transocks
go get github.com/BurntSushi/toml
go get github.com/slene/dnsproxy
go get github.com/miekg/dns
go get github.com/pmylund/go-cache

cd $BUILD_DIR

go build -v -o transocks -a -tags netgo -installsuffix netgo src/github.com/cybozu-go/transocks/cmd/transocks/main.go
go build -v -o dnsproxy -a -tags netgo -installsuffix netgo src/github.com/slene/dnsproxy/*.go

cd $DIR

docker build -t wadahiro/docker-proxy .

