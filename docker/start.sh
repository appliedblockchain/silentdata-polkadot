#!/bin/bash

./substrate-node/target/release/node-template --dev --ws-external &

cd /node-fe && yarn start &

wait -n

exit $?
