# wifi_broadcast
Connection-less WiFi data transmission project

To compile natively use:
  - make all
  
To crosscompile explicitly to Raspberry Pi download:
  - git clone https://github.com/raspberrypi/tools
  - You can then copy the  /tools/arm-bcm2708/gcc-linaro-arm-linux-gnueabihf-raspbian directory to a common location, and add  /tools/arm-bcm2708/gcc-linaro-arm-linux-gnueabihf-raspbian/ to the TOOLS_PATH varible in the Makefile. For 64-bit host systems, use  /tools/arm-bcm2708/gcc-linaro-arm-linux-gnueabihf-raspbian-x64/
  - make armhf
  
Do not forget to clean already compiled files between changes from host compilation to cross compilation and vise versa by:
  - make clean
