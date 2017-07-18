# wifi_broadcast  [![BCH compliance](https://bettercodehub.com/edge/badge/dmitry-kutergin/wifi_broadcast)](https://bettercodehub.com/)
P2P WiFi data transmission project

To compile natively use:
  - make all
  
To crosscompile explicitly to Raspberry Pi download:
  - git clone https://github.com/raspberrypi/tools
  - You can then copy the  /tools/arm-bcm2708/gcc-linaro-arm-linux-gnueabihf-raspbian directory to a common location, and add  /tools/arm-bcm2708/gcc-linaro-arm-linux-gnueabihf-raspbian/ to the TOOLS_PATH varible in the Makefile. For 64-bit host systems, use  /tools/arm-bcm2708/gcc-linaro-arm-linux-gnueabihf-raspbian-x64/
  - make armhf
  
Do not forget to clean already compiled files between changes from host compilation to cross compilation and vise versa by:
  - make clean
  
Data integrity test example.
To test data integrity the following shell pipeline can be used:
  - ./traffic_gen -r 2000000|tee dump_orig|./tx -p 0 -a 78 -i 48 wlan0|tee dump_tx|./rx -p 0 wlan0|pv>dump
  - Wait several minutes, then Ctrl^c
  - cat dump_orig | sed -r -e "s/;/\n/g" >dump_orig_n; cat dump | sed -r -e "s/;/\n/g" >dump_n;vimdiff dump_orig_n dump_n
Discprepancies are normal to be seen at the end, since Ctrl^c kills different processes in different times.
