make -j 16 APP=client WERROR=0 &&\
cp build/native/xbee-client.native  ./xbee-client.native &&\
./xbee-client.native /dev/ttyUSB1