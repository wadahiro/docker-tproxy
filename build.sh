#!/bin/sh

DIR=$(cd $(dirname $0); pwd)
cd $DIR

go build -v -o bin/tproxy -a -tags netgo -installsuffix netgo tproxy.go

docker build $@ -t wadahiro/docker-tproxy .

