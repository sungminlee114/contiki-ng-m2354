echo $0 $1
if [ "$1" = "" ]; then
  echo "Usage: $0 <COM port number>"
  exit
fi

BOARD=ASM2
COM=COM$1
echo "${BOARD}, ${COM}"

make TARGET=m2354 -j 16 WERROR=0 && \
../../../axtool.exe -t nu_maker -f2 ./build/m2354/ASM2/udp-client.bin $COM