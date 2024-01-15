# AcCCS
Access Capabilities for CCS (AcCCS - pronounced "access" /ˈakˌses/) provides a flexible and inexpensive solution to enable communications testing of various Electric Vehicle (EV) technologies that use the CCS charging standard(s).  This codebase is an example of tools and scripts capable of communicating with and emulating an Electric Vehicle Communications Controller (EVCC) and/or a Supply Equipment Communications Controller (SECC).

This project is the result of our efforts to find COTS hardware and existing open source software capable of communicating via HomePlug GreenPHY (HPGP) with CCS enabled vehicles and charging stations.  We are providing some basic scripts to emulate an EV (see [PEV.py](PEV.py)) or an EVSE (see [EVSE.py](EVSE.py)).  These two scripts utilize third-party open source projects that provide Scapy packet definitions for Layer 2 (HPGP - [layerscapy](/layerscapy/)) and Layer 3 (DIN/ISO - [layers](/layers/)). Our goal was to establish a persistent network connection with a target device so that we can test the device for network vulnerabilities.

To enable some testing of the IPv6 endpoints, the emulator scripts provide the ability to perform some basic port scans of the target.  This functionality is available using command-line options of the emulator.  The emulators can be further enhanced for additional port scanning activities or even fuzz testing of the selected CCS protocol.

The emulators utilize a Java program ([java_decoder](/java_decoder/)) to encode and decode the XML messages exchanged between an EV and EVSE.  This decoder is from the [V2Gdecoder](https://github.com/FlUxIuS/V2Gdecoder) project and has been patched to fix a couple of bugs identified during our testing.  The Java server is started automatically when executing one of the emulators.

**Note:** This code was primarily developed and tested using the old DIN 70121 specification and schema. The newer ISO 15118-2:2010 standard is included but has not been tested.

A description of the [CurrentImplementation](/docs/CurrentImplementation.md) of our AcCCS box, as well as some supporting presentations, are found in the [docs](/docs/) folder.

**A final word:** All of this code was generated in our lab using extensive trial and error while monitoring communications between a couple EV and EVSE.  It has not been extensively tested with many vehicles or charging stations.  It was not written using formal software development and design methods.  We were just happy when it worked.  It is not pretty.

## Getting Started
In order to include the third-party libraries when cloning AcCCS, use the proper git options.  For example:

```
git clone --recurse-submodules <clone url>
git submodule sync
```

If you encounter errors about git not locating specific repository versions, using this dirty hack seems to work:

```
git submodule update --force --recursive --init --remote
```

## Hardware Configuration

Details regarding our current implementation and hardware configuration is found in the '''docs''' folder.

The ```resources``` directory includes the schematics and design files to create the PWM board used to emulate the SECC.  The following shows how all of the hardware is currently setup in the AcCCS boxes.

EVSE DEVOLO: [EVSE side configured dLAN Green Phy Eval Board](https://www.codico.com/en/evse-side-configured-dlan-green-phy-eval-board)\
PEV DEVOLO: [PEV side configured dLAN Green Phy Eval Board](https://www.codico.com/en/pev-side-configured-dlan-green-phy-eval-board)\
RASPBERRY PI: [Raspberry Pi 4 Model B](https://www.raspberrypi.com/products/raspberry-pi-4-model-b/)\
RELAY: [4 Channel 5V Relay](https://www.sunfounder.com/products/4channel-relay-shield)\
12V OUT: [12V Isolated DC/DC Converter](https://www.digikey.com/en/products/detail/cui-inc./PYBE30-Q24-S12-T/9859982)\
5V OUT: [5V Isolated DC/DC Converter](https://www.digikey.com/en/products/detail/cui-inc/PYBE30-Q24-S5-T/9859981)\
ETH: [USB to RJ45 Adapter](https://www.amazon.com/Gigabit-Adapter-CableCreation-Network-Supporting/dp/B07CKQY8HN)\
555 Timer: [TLC555CP](https://www.digikey.com/en/products/detail/texas-instruments/TLC555CP/277502)\
Op-Amp: [TLE2142AMJG](https://www.ti.com/product/TLE2142)

The devices labeled ETH, RELAY, 5V OUT, 12V OUT, and RASPBERRY PI are generic devices so a specific brand is not required. Nevertheless, I have linked above the exact version of these devices we used in the AcCCS box. A brief description of each of these devices are as follows so that any devices that fits this description can probably be used with little to no alteration. Extra notes regarding the implementation and role of each device are also included.

RASPBERRY PI: For this project a raspberry pi was used, but any computer or microcontroller can be used in its place. A pi was used for its small form factor, easily configurable GPIO, and ability to run an OS. Whatever device is used for this role must support the following features: IPv4 and IPv6 networking, 4 digital GPIO outputs, 3 RJ-45 ports or the ability to connect RJ-45 adapters, and python support (unless you don't want to use the scripts provided in this project).

RELAY: For the purposes of this project and relay or switching device can be used. For the hardware implementation of the AcCCS box, 4 channels are used which are controlled by the digital GPIO output of the Raspberry Pi. The first two channels of the relay are used to emulate the J1772 states of a PEV. The J1772 signaling circuit below shows the resistance values used (found in the vehicle controller portion labeled R3 and R2). The next 2 channels are used to connect and disconnect the control pilot and proximity pilot lines for the EVSE emulation to mimic plugging and unplugging the charging cable. When connected, the control pilot line goes directly to the output and the proximity pilot ties a resistance to ground in accordance to the J1772 standard (R6 in the EVSE connector of the signaling circuit).

12V/5V OUT: These DC/DC power converters were used as a means to get +12V,-12V, and +5V power supplies, so they are not necessary if you have a way to supply these voltages by other means. If the provided configuration is used, the converters must be **ISOLATED** DC/DC converters so that you can tie the positive terminal of one 12V supply to the negative terminal of the other in order to create a -12V supply.

ETH: Any generic USB to RJ-45 adapter can be used. This is needed so that the Raspberry pi can interface with the two Devolo radios via ethernet. Not necessary if your choice of controller has 3 RJ-45 ports.

EVSE/PEV DEVOLO: The Devolo eval board used acts as a radio that bridges ethernet communications over cat cable to HomePlug GreenPHY communications over a single signal wire and ground. These boards also automatically complete some of the level 2 HomePlug protocol specific actions, such as forming ALVNs according to the standard, so to work properly must be configured properly. Currently, these radios are purchased pre-configured from Devolo, but there may be some way to flash an unconfigured board with the contents of a configured board. There are also some jumper options present on the eval boards which should be configured so that the HomePlug GreenPHY is output over the two-wire terminal instead of coax.

![Alt text](/resources/AcCCS_Box_BG.png?raw=true "AcCCS Box Layout")

The circuit shown below is what is used to generate the +12V to -12V 1kHz 5% Duty Cycle PWM signal that is supplied by the EVSE controller. It uses the TLC555CP chip to first generate a +12V to 0V 1kHz 5% Duty Cycle PWM. Other timer ICs could probably be used, but this is what worked for me. The output PWM's frequency and duty cycle are dependant on the values of two resistors and one capacitor (the 1.5k and 25k Ohm resistors and the 47 nanoFarad capacitor). In practice, the values of these components varied enough for the resulting signal to not fit within tolerances for the EVCC to recognize it as a 1kHz 5% PWM. So, in place of a 1.5k resistance a 10k potentiometer was used and in place of a 25k resistance a 22k resistor in series with a 10k potentiometer was used. In this configuration, the output of the 555 timer was probed with an oscilloscope and the potentiometers were tuned until the PWM was as close to the spec as possible. Next, the signal along with -12V DC is input into an Op-Amp so that the resulting output will be the required +12V to -12V PWM. The Op-Amp used is very high speed and maybe overkill, so you may be able to get away with a cheaper IC but this is what worked for me. In practice, the resulting PWM is closer to an +11V peak than +12V, so to compensate the resistor in series with the output was changed to a lower value (from a 1k Ohm to a 680 Ohm resistor). This is done so that when the PEV changes its internal resistances and changes the J1772 states, the resulting voltages are closer to the +9V and +6V peaks required by the standard.

![Alt text](/resources/PWM.png?raw=true "PWM Circuit")

![Alt text](/resources/J1772_BG.png?raw=true "J1772 Signaling Circuit")

## Software Configuration

The DIN and ISO standards define that the TCP/IP communication between EVCC and SECC equipment use IPv6 networking with link-local addressing. For this reason, to properly communicate to these devices from a controller, IPv6 networking on the controller must be configured for link-local addressing on the interfaces that connect to the Devolo radios.

### Python module dependencies:
* scapy
* tqdm
* smbus

**Scapy** is used for all of the packet activities such as crafting, manipulation, sending, and receiving packets. 

**TQDM** is used for neat progress bars in scripts involving the custom NMAP functionality for scanning SECC and EVCC devices. Custom scapy packets provided by the [HomePlugPWN](https://github.com/FlUxIuS/HomePlugPWN) project are included in the [layerscapy](/layerscapy/) folder. 

**Smbus** is used for I2C communications with the PCB to operate the relays.  This replaces previous code where GPIO pins from the RASPBERRY PI were used for relay operation.

Below is a brief description of the scripts in this project. These scripts are provided as examples of how you might utilize this hardware in your own testing environment. This is not intended to be a finished product with all desired functionality. Some functionality is still a work in progress.

**EVSE.py:** This script emulates an EVSE when run. When the AcCCS's EVSE CP and SIG GND are connected to the PEV's CP and GND, the script follows the J1772 spec by going through layer 2 HomePlug GreenPHY SLAC negotiations, layer 3 UDP SECC Discovery Protocol, and then layer 3 TCP/IPv6 communications. Currently, the TCP/IPv6 communications only support the DIN spec, but future work includes implementing the ISO-2 and ISO-20 specs which are required for TLS encrypted sessions, Plug-n-charge, and 2-way power transfer.

**PEV.py:** Same as EVSE.py, but AcCCS's PEV CP and SIG GND should be connected to the EVSE's CP and GND pins.

**MIM.py:** **NOT IMPLEMENTED** | Forms two separate connections to a PEV and EVSE simultaneously. Will forward packets from one conversation to the other, changing the contents if specified by the user. Cannot form a simple bridge between the two because of high amounts of cross-talk between CP lines. This protocol is very susceptible to RF interference.

**EXIProcessor.py:** Python wrapper for using the java webserver EXI processor found in the java_decoder folder. This project uses a modified version of the jar file provided by the [V2Gdecoder](https://github.com/FlUxIuS/V2Gdecoder) project which itself is based on the [RISE-V2G](https://github.com/SwitchEV/RISE-V2G) project. This modified jar file is named V2GdecoderMOD.jar and adds functionality to specify which port the webserver will listen on as well as an argument to specify with which schema to encode and decode (DIN vs ISO-2 vs ISO-20).

**XMLBuilder.py:** Python script used to create and manipulate XML payloads that follow the DIN and ISO specs. The default values for each of these packet types are taken from real values that were used by EVSEs and PEVs captured during a normal charging session.

### Current TODOs:
* Implement ISO 15118-2:2010, ISO 15118-2:2015 and ISO 15118-20 spec into XML builder script and emulator scripts
* Complete and test MIM script
* Make scripts more user friendly (ex. add cmd line args instead of commenting out code)
* Find a working EXI processor that isn't a java webserver :)

## Notes

Only three scripts are expected to be run from command line: EVSE.py, PEV.py, and MIM.py. The other scripts and files serve as tools and utilities for these scripts to run. 

The ```EVSE.py``` and ```PEV.py``` scripts include some basic functionality to port scan (similar to NMAP) while the emulator is running. In my limited testing the EVSEs stay connected to the emulator indefinitely, but the PEVs terminate the connection after a couple of minutes without any power transfer. For this reason a simple TCP syn scan is included in the script to pick up where the scan left off when the connection is reestablished.