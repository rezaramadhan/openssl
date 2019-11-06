#!/usr/bin/env bash
set -e

OPENSSL_DIR=/opt/openssl
OPENSSL_SRC_DIR=../openssl
echo "PATH=\"$PATH:$OPENSSL_DIR/bin\"" | sudo tee /etc/environment

cd $OPENSSL_SRC_DIR
./config no-asm enable-unit-test -v --prefix=$OPENSSL_DIR --openssldir=$OPENSSL_DIR/ssl --debug
printf "###############################################################\n\n\n"
printf "###############################################################\n"
sudo rm -rf $OPENSSL_DIR
make clean
printf "###############################################################\n\n\n"
printf "###############################################################\n"
make
printf "###############################################################\n\n\n"
printf "###############################################################\n"
make test
printf "###############################################################\n\n\n"
printf "###############################################################\n"
sudo make install
printf "###############################################################\n\n\n"
printf "###############################################################\n"
sudo cp -rv $OPENSSL_DIR/include/* /usr/include/
sudo mv /usr/bin/openssl /usr/bin/openssl.original
sudo mv /usr/bin/c_rehash /usr/bin/c_rehash.original
echo "$OPENSSL_DIR/lib" | sudo tee /etc/ld.so.conf.d/openssl.conf
printf "###############################################################\n\n\n"
printf "###############################################################\n"
sudo ldconfig -v
printf "###############################################################\n\n\n"
printf "###############################################################\n"
echo "PKG_CONFIG_PATH=\"/opt/openssl/lib/pkgconfig/\"" | sudo tee -a /etc/environment
source /etc/environment
