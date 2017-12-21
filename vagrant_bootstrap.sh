#!/bin/sh

apt-get update
apt-get install -y curl wget build-essential git
curl https://sh.rustup.rs -sSf > rustup.sh
sh rustup.sh -y
echo "export PATH=$HOME/.cargo/bin:$PATH" >> ~/.bashrc
