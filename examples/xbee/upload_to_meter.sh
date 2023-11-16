echo $0 $1
if [ "$1" = "" ]; then
  echo "Usage: $0 <COM port number>"
  exit
fi

BOARD=ASM2
COM=COM$1
echo "${BOARD}, ${COM}"

make -j 16 TARGET=m2354
../../../axtool.exe -t nu_maker -f2 ./build/m2354/ASM2/xbee-client.bin $COM