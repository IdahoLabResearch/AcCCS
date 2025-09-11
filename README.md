# AcCCS
Access Capabilities for CCS (AcCCS - pronounced "access" /ˈakˌses/) provides a flexible and inexpensive solution to enable communications testing of various Electric Vehicle (EV) technologies that use the CCS charging standard(s).  This codebase is an example of tools and scripts capable of communicating with and emulating an Electric Vehicle Communications Controller (EVCC) and/or a Supply Equipment Communications Controller (SECC).

This project is the result of our efforts to find COTS hardware and existing open source software capable of communicating via HomePlug GreenPHY (HPGP) with CCS enabled vehicles and charging stations.  We provide a unified emulator script ([Emulator.py](Emulator.py)) that can emulate either an EV (PEV mode) or an EVSE (EVSE mode) using command-line arguments. The emulator utilizes third-party open source projects that provide Scapy packet definitions for Layer 2 (HPGP - [HomePlugPWN](external_libs/HomePlugPWN/)) and uses the Python EXPy library for EXI encoding/decoding.

The emulator utilizes the Python [EXPy library](external_libs/EXPy/) for encoding and decoding the XML messages (EXI format) exchanged between an EV and EVSE. This replaces the previous Java-based approach, eliminating the need for a separate Java runtime environment and providing better integration with the Python codebase.

A description of the [CurrentImplementation](/docs/CurrentImplementation.md) of our AcCCS box, as well as some supporting presentations, are found in the [docs](/docs/) folder.

**A final word:** All of this code was generated in our lab using extensive trial and error while monitoring communications between a couple EV and EVSE.  It has not been extensively tested with many vehicles or charging stations.  It was not written using formal software development and design methods.  We were just happy when it worked.  It is not pretty.

## Getting Started
In order to include the third-party libraries when cloning AcCCS, use the proper git options.  For example:

```
git clone --recurse-submodules <clone url>
git submodule sync
```

If you encounter errors about git not locating specific repository versions or do not clone with the ``--recurse-submodules`` flag, using this dirty hack seems to work:

```
git submodule update --force --recursive --init --remote
```

### Building the Project
The project now includes a Makefile that builds the necessary components:

```
make all
```

This will build the EXPy library and any other required components.

## Hardware Configuration

Details regarding our current implementation and hardware configuration is found in the '''docs''' folder.

The ```resources``` directory includes the schematics and design files to create the PWM board used to emulate the SECC.  The following shows how all of the hardware is currently setup in the AcCCS boxes.

EVSE DEVOLO: [EVSE side configured dLAN Green Phy Eval Board](https://www.codico.com/en/evse-side-configured-dlan-green-phy-eval-board)\
PEV DEVOLO: [PEV side configured dLAN Green Phy Eval Board](https://www.codico.com/en/pev-side-configured-dlan-green-phy-eval-board)\
RASPBERRY PI: [Raspberry Pi 4 Model B](https://www.raspberrypi.com/products/raspberry-pi-4-model-b/)\
12V OUT: [12V Isolated DC/DC Converter](https://www.digikey.com/en/products/detail/cui-inc./PYBE30-Q24-S12-T/9859982)\
5V OUT: [5V Isolated DC/DC Converter](https://www.digikey.com/en/products/detail/cui-inc/PYBE30-Q24-S5-T/9859981)\
ETH: [USB to RJ45 Adapter](https://www.amazon.com/Gigabit-Adapter-CableCreation-Network-Supporting/dp/B07CKQY8HN)\
PWM PCB: [PWM PCB](PCB/AcCCS_Base_Module_PCB/)

The devices labeled ETH, RELAY, 5V OUT, 12V OUT, and RASPBERRY PI are generic devices so a specific brand is not required. Nevertheless, the above links provided are the exact version of these devices we used in our AcCCS box. A brief description of each of these devices are as follows so that any devices that fits this description can probably be used with little to no alteration. Extra notes regarding the implementation and role of each device are also included.

**RASPBERRY PI:** For this project a raspberry pi was used, but any computer or microcontroller can be used in its place. A pi was used for its small form factor, I2C interface, and ability to run an OS. Whatever device is used for this role must support the following features: IPv4 and IPv6 networking, I2C interface (PWM board), 3 RJ-45 ports or the ability to connect RJ-45 adapters, and python support (unless you don't want to use the scripts provided in this project).

**PWM PCB and RELAYS:** The PWM circuit includes several on-board relays. The first two channels of the relay are used to emulate the J1772 states of a PEV. The J1772 signaling circuit below shows the resistance values used (found in the vehicle controller portion labeled R3 and R2). The next 2 channels are used to connect and disconnect the control pilot and proximity pilot lines for the EVSE emulation to mimic plugging and unplugging the charging cable. When connected, the control pilot line goes directly to the output and the proximity pilot ties a resistance to ground in accordance to the J1772 standard (R6 in the EVSE connector of the signaling circuit).

**12V/5V OUT:** These DC/DC power converters were used as a means to get +12V,-12V, and +5V power supplies, so they are not necessary if you have a way to supply these voltages by other means. If the provided configuration is used, the converters must be **ISOLATED** DC/DC converters so that you can tie the positive terminal of one 12V supply to the negative terminal of the other in order to create a -12V supply.

**ETH:** Any generic USB to RJ-45 adapter can be used. This is needed so that the Raspberry pi can interface with the two Devolo radios via ethernet. Not necessary if your choice of controller has 3 RJ-45 ports.

**EVSE/PEV DEVOLO:** The Devolo eval board used acts as a radio that bridges ethernet communications over cat cable to HomePlug GreenPHY communications over a single signal wire and ground. These boards also automatically complete some of the level 2 HomePlug protocol specific actions, such as forming ALVNs according to the standard, so to work properly must be configured properly. Currently, these radios are purchased pre-configured from Devolo, but there may be some way to flash an unconfigured board with the contents of a configured board. There are also some jumper options present on the eval boards which should be configured so that the HomePlug GreenPHY is output over the two-wire terminal instead of coax.

![Alt text](/resources/AcCCS_Box_BG.png?raw=true "AcCCS Box Layout")

The circuit shown below is what is used to generate the +12V to -12V 1kHz 5% Duty Cycle PWM signal that is supplied by the EVSE controller. It uses the TLC555CP chip to first generate a +12V to 0V 1kHz 5% Duty Cycle PWM. Other timer ICs could probably be used, but this is what worked for me. The output PWM's frequency and duty cycle are dependant on the values of two resistors and one capacitor (the 1.5k and 25k Ohm resistors and the 47 nanoFarad capacitor). In practice, the values of these components varied enough for the resulting signal to not fit within tolerances for the EVCC to recognize it as a 1kHz 5% PWM. So, in place of a 1.5k resistance a 10k potentiometer was used and in place of a 25k resistance a 22k resistor in series with a 10k potentiometer was used. In this configuration, the output of the 555 timer was probed with an oscilloscope and the potentiometers were tuned until the PWM was as close to the spec as possible. Next, the signal along with -12V DC is input into an Op-Amp so that the resulting output will be the required +12V to -12V PWM. In practice, the resulting PWM is closer to an +11V peak than +12V, so to compensate the resistor in series with the output was changed to a lower value (from a 1k Ohm to a 680 Ohm resistor). This is done so that when the PEV changes its internal resistances and changes the J1772 states, the resulting voltages are closer to the +9V and +6V peaks required by the standard.

555 Timer: [TLC555CP](https://www.digikey.com/en/products/detail/texas-instruments/TLC555CP/277502)\
Op-Amp: [LM6132BIN/NOPB](https://www.ti.com/product/LM6132/part-details/LM6132BIN/NOPB)

![Alt text](/resources/PWM.png?raw=true "Basic PWM Generation Circuit")

![Alt text](/resources/J1772_BG.png?raw=true "SAE J1772 Signaling Circuit")

## PCB Design Files

The project includes KiCad design files for custom PCBs:

**AcCCS Base Module PCB:** Located in [PCB/AcCCS_Base_Module_PCB/](PCB/AcCCS_Base_Module_PCB/), this contains the main control circuitry including the PWM generation circuit described above.

**AcCCS Siphon Module PCB:** Located in [PCB/AcCCS_Siphon_Module_PCB/](PCB/AcCCS_Siphon_Module_PCB/), this is an additional module for enhanced signal monitoring and injection capabilities.

Both PCB designs include:
- KiCad schematic (.kicad_sch) and PCB layout (.kicad_pcb) files
- Bill of Materials (BOM) 
- Project files and version history in backup folders

## Software Configuration

The DIN and ISO standards define that the TCP/IP communication between EVCC and SECC equipment use IPv6 networking with link-local addressing. For this reason, to properly communicate to these devices from a controller, IPv6 networking on the controller must be configured for link-local addressing on the interfaces that connect to the Devolo radios.

### Python Module Dependencies
* scapy
* tqdm
* smbus

**Scapy** is used for all of the packet activities such as crafting, manipulation, sending, and receiving packets. 

**TQDM** is used for neat progress bars in scripts involving the custom NMAP functionality for scanning SECC and EVCC devices.

**Smbus** is used for I2C communications with the PCB to operate the relays found on the PWM PCB.

### Emulator Architecture
The project has been rewritten using a simple state machine architecture to better track how the system communicates with PEVs and EVSEs

**Emulator.py:** The main unified emulator script that can operate in either PEV or EVSE mode. Usage:
```
python Emulator.py --type EVSE    # Run as EVSE (charging station)
python Emulator.py --type PEV     # Run as PEV (electric vehicle)
```

The emulator supports various command-line options including:
- `--mode`: Operation mode
- `--protocol`: Protocol version (DIN, ISO2, ISO20)
- `--debug`: Enable debug logging
- `--timeout`: Connection timeout value
- See the [Usage Examples](#Usage-Examples) for a comprehensive list of arguements

**EmulatorStateMachine.py:** Core state machine implementation that manages the communication flow through different protocol states.

**State Modules:** The communication logic is organized into modular state classes:
- `States_SLAC.py`: HomePlug GreenPHY SLAC states
- `States_AppHand.py`: Handshake states  
- `States_DIN.py`: DIN 70121 protocol states
- `States_TCP.py`: TCP connection management states
- `States_SECC.py`: SECC specific states

**V2Gjson.py:** JSON-based message handling for V2G communications, replacing the previous XML-based approach.

**Deprecated Scripts:** The previous `EVSE.py` and `PEV.py` scripts have been replaced by the unified `Emulator.py`.

### Recent Updates
* **State Machine Architecture:** Completely refactored the emulator to use a state machine design
* **Python EXI Processing:** Replaced Java EXI processor with Python EXPy library, eliminating Java dependency
* **Unified Emulator:** Combined separate PEV.py and EVSE.py scripts into a single configurable Emulator.py

### Current TODOs:
* Update EXPy project to support ISO 15118-2 and ISO 15118-20
* Implement ISO 15118-2 and ISO 15118-20 spec into the new state machine architecture
* Re-implement working NMAP scanner within Emulator script

## Usage Examples

The main script to run from command line is `Emulator.py`. The other scripts and files serve as supporting modules and utilities.

Help Command:
```
usage: Emulator.py [-h] [-M {0,1,2}] [-T {pev,evse}] [-P {DIN,ISO-2,ISO-20}] [-I INTERFACE] [--modified-cordset] [-V] [--source-mac SOURCE_MAC] [--source-ip SOURCE_IP] [--source-port SOURCE_PORT] [--NID NID] [--NMK NMK] [-d] [-t TIMEOUT]
               [--portscan-MAC PORTSCAN_MAC] [--portscan-IP PORTSCAN_IP] [--portscan-ports PORTSCAN_PORTS]

AcCCS (Access Through CCS): Emulate a PEV or EVSE -- Default values shown in [square brackets]

options:
  -h, --help            show this help message and exit
  -M {0,1,2}, --mode {0,1,2}
                        Emulator mode: [0=Full], 1=Stall, 2=Scan
  -T {pev,evse}, --type {pev,evse}
                        Emulator type: [EVSE] or PEV
  -P {DIN,ISO-2,ISO-20}, --protocol {DIN,ISO-2,ISO-20}
                        Protocol to use for EXI encoding: [DIN], ISO-2, ISO-20
  -I INTERFACE, --interface INTERFACE
                        Interface to listen on: [ethevse], ethpev, etc.
  --modified-cordset    Enable modified cordset: [false]
  -V, --virtual         Enable virtual mode: [false]
  --source-mac SOURCE_MAC
                        Specify source MAC address (optional)
  --source-ip SOURCE_IP
                        Specify source IP address (optional)
  --source-port SOURCE_PORT
                        Specify source port (optional)
  --NID NID             Specify Network ID (optional)
  --NMK NMK             Specify Network Membership Key (optional)
  -d, --debug           Enable debug mode: [false]
  -t TIMEOUT, --timeout TIMEOUT
                        Timeout for connection reset in seconds: [5]
  --portscan-MAC PORTSCAN_MAC
                        MAC address for port scanning (required if in mode 2)
  --portscan-IP PORTSCAN_IP
                        IP address for port scanning (required if in mode 2)
  --portscan-ports PORTSCAN_PORTS
                        List of ports to scan separated by commas (ex. 1,2,5-10,19,...) (default: Top 8000 common ports)
```

Basic Usage:
```bash
sudo python Emulator.py -T pev -V -t 20

# This starts a PEV emulator without using the I2C relays on the PCB with a timeout of 20 seconds

sudo python Emulator.py -T evse -d -I lo

# This starts an EVSE emulator in debug mode on the loopback interface
```

