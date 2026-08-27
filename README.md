# AcCCS
Access Capabilities for CCS (AcCCS - pronounced "access" /ˈakˌses/) provides a flexible and inexpensive solution to enable communications testing of various Electric Vehicle (EV) technologies that use the CCS charging standard(s).  This codebase is an example of tools and scripts capable of communicating with and emulating an Electric Vehicle Communications Controller (EVCC) and/or a Supply Equipment Communications Controller (SECC).

This project is the result of our efforts to find COTS hardware and existing open source software capable of communicating via HomePlug GreenPHY (HPGP) with CCS enabled vehicles and charging stations.  We are providing some basic scripts to emulate an EV (see [run_evcc.py](run_evcc.py)) or an EVSE (see [run_secc.py](run_secc.py)).  These two scripts utilize a third-party open source project that provide Scapy packet definitions for Layer 2 (HPGP - [layerscapy](https://github.com/FlUxIuS/HomePlugPWN/tree/master/layerscapy)). Our goal was to establish a persistent network connection with a target device so that we can test the device for network vulnerabilities.

To enable some testing of the IPv6 endpoints, the emulator scripts provide the ability to perform some basic port scans of the target.  This functionality is available using command-line options of the emulator.  The emulators can be further enhanced for additional port scanning activities or even fuzz testing of the selected CCS protocol.

> **Note:** This code was primarily developed and tested using the old DIN 70121 specification and schema.

A description of the [CurrentImplementation](/docs/CurrentImplementation.md) of our AcCCS box, as well as some supporting presentations, are found in the [docs](/docs/) folder.

**A final word:** All of this code was generated in our lab using extensive trial and error while monitoring communications between a couple EV and EVSE.  It has not been extensively tested with many vehicles or charging stations.  It was not written using formal software development and design methods.  We were just happy when it worked.  It is not pretty.

## Getting Started

For the full fresh-clone walkthrough — submodule clone, Python dependencies,
PKI certificates, the virtual veth pair, and a smoke test — see
[Project Setup](#project-setup).

## Hardware Configuration

Details regarding our current implementation and hardware configuration is found in the '''docs''' folder.

The ```resources``` directory includes the schematics and design files to create the PWM board used to emulate the SECC.  The following shows how all of the hardware is currently setup in the AcCCS boxes.

EVSE DEVOLO: [EVSE side configured dLAN Green Phy Eval Board](https://www.codico.com/en/evse-side-configured-dlan-green-phy-eval-board)\
PEV DEVOLO: [PEV side configured dLAN Green Phy Eval Board](https://www.codico.com/en/pev-side-configured-dlan-green-phy-eval-board)\
RASPBERRY PI: [Raspberry Pi 4 Model B](https://www.raspberrypi.com/products/raspberry-pi-4-model-b/)\
12V OUT: [12V Isolated DC/DC Converter](https://www.digikey.com/en/products/detail/cui-inc./PYBE30-Q24-S12-T/9859982)\
5V OUT: [5V Isolated DC/DC Converter](https://www.digikey.com/en/products/detail/cui-inc/PYBE30-Q24-S5-T/9859981)\
ETH: [USB to RJ45 Adapter](https://www.amazon.com/Gigabit-Adapter-CableCreation-Network-Supporting/dp/B07CKQY8HN)\
PWM PCB: [PWM PCB](resources/PWM_PCB/)

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

## Software Configuration

The DIN and ISO standards define that the TCP/IP communication between EVCC and SECC equipment use IPv6 networking with link-local addressing. For this reason, to properly communicate to these devices from a controller, IPv6 networking on the controller must be configured for link-local addressing on the interfaces that connect to the Devolo radios.

### Python Module Dependencies
* scapy
* smbus
* expy

**Scapy** is used for all of the packet activities such as crafting, manipulation, sending, and receiving packets. 

**Smbus** is used for I2C communications with the PCB to operate the relays found on the PWM PCB.

**EXPy** is the Python binding over LF Energy EVerest's `libcbv2g` used for EXI
encode/decode (see [ADR-0002](docs/adr/0002-expy-codec-replacement.md)). EXPy is
installed from source and builds a C/C++ extension during `pip install`, which
adds the following install-time prerequisites on every target (dev machine and
Raspberry Pi alike):

* **CMake** ≥ 3.20
* **Ninja** ≥ 1.10
* A C/C++ toolchain (gcc/clang and the matching standard libraries)

Install these *before* `pip install` — [Project Setup](#project-setup) step 2
covers the Debian / Raspberry Pi OS one-liner.

### EVSE and EV Python Scripts
Below is a brief description of the entry-point scripts in this project. These scripts are provided as examples of how you might utilize this hardware in your own testing environment. This is not intended to be a finished product with all desired functionality. Some functionality is still a work in progress.

**run_secc.py:** Emulates an EVSE (SECC). When the AcCCS's EVSE CP and SIG GND are connected to the PEV's CP and GND, the script follows the J1772 spec by going through layer 2 HomePlug GreenPHY SLAC negotiations, layer 3 UDP SECC Discovery Protocol, and then layer 3 TCP/IPv6 communications. DIN SPEC 70121, ISO 15118-2, and ISO 15118-20 (AC and DC) are all supported, including TLS sessions, Plug & Charge, and bidirectional power transfer; which one a run speaks is chosen by the personality's `capabilities.supported_protocols` (see [Running the emulators](#running-the-emulators)).

**run_evcc.py:** Same as run_secc.py but for the EV side (EVCC); AcCCS's PEV CP and SIG GND should be connected to the EVSE's CP and GND pins.

A man-in-the-middle mode — two simultaneous connections to a PEV and an EVSE with packets forwarded (and optionally modified) between them — remains unimplemented. A simple bridge between the two is not workable because of the high cross-talk between CP lines, and the signalling is very susceptible to RF interference.

### Hardware bench tools

These helper scripts drive the I2C relay board directly, without loading a personality or opening a V2G session. They run only on the hardware host (the Pi, with the relay board on I2C bus 1); off the hardware — no `smbus`, no bus, or no permission on `/dev/i2c-1` — each exits with a one-line explanation rather than a traceback.

**scripts/evcc_relays.py:** Interactive control of the EV side's control-pilot relays for exercising the CP/PP wiring in isolation. Type a J1772 state (`a`/`b`/`c`) and watch the EVSE react; the relays are always opened again on exit. Like the emulator it touches only the EV side's pins, so a SECC running on the same box keeps its relays.

**scripts/reset_relays.py:** Turns *every* relay off in one deliberate whole-register write, regardless of which role set the bits. This recovers a board whose relays a hard-killed emulator left latched closed — the one case the per-role writes cannot clean up, since the owner is no longer around to clear them. It is the single sanctioned exception to the role-ownership rule (see [ADR-0007](docs/adr/0007-role-scoped-relay-ownership.md)); the pin-direction configuration is left untouched. **Do not run it while an emulator is live** — the same broad write that recovers an orphaned board will clear a healthy session's relays out from under it. It reports whether it cleared anything or found the board already off.

## Project Setup

This is the single, linear path from a fresh clone to a green virtual demo
session. Follow it top to bottom — each step is a prerequisite for the smoke
test at the end. The deeper reference sections below are linked from each step.

### 1. Clone with submodules

AcCCS vendors its third-party Layer 2 (HPGP) libraries as git submodules, so a
plain `git clone` is not enough:

```bash
git clone --recurse-submodules <clone-url>
cd AcCCS
git submodule sync
```

If git errors about locating specific repository versions, this usually
unsticks it:

```bash
git submodule update --force --recursive --init --remote
```

### 2. Python environment + dependencies

Use Python 3.10+ in an isolated environment — a `conda` env or a `venv` both
work. The pinned dependencies live in [`requirements.txt`](requirements.txt):

```bash
# conda
conda create -n AcCCS python=3.11 && conda activate AcCCS
# — or — venv
python -m venv .venv && source .venv/bin/activate

pip install -r requirements.txt
```

One dependency, **EXPy**, builds a C/C++ extension at install time (see
[ADR-0002](docs/adr/0002-expy-codec-replacement.md)), so a build toolchain
must be present *before* `pip install`. On Debian / Raspberry Pi OS:

```bash
sudo apt install cmake ninja-build build-essential
```

See [Software Configuration](#software-configuration) for the full dependency
rundown.

### 3. Generate PKI certificates

The stock personalities ship with TLS enabled (`tls.use_tls: true`,
`tls.enable_tls_1_3: true`), so the SECC needs a server certificate chain
before it can complete SDP/TLS. Generate it from the repo root:

```bash
bash app/shared/pki/create_certs.sh -v iso-2
```

Skipping this step is the most common first-run failure — it surfaces as
`FileNotFoundError: oemRootCACert.pem` followed by a cascading
`'TCPServer' object has no attribute 'ipv6_address_host'` traceback.

If you intend to run ISO 15118-20 scenarios, also generate the `-v iso-20`
chain:

```bash
bash app/shared/pki/create_certs.sh -v iso-20
```

See [Certificate Management](#certificate-management) for the Plug-and-Charge
context.

### 4. Create the virtual veth pair

The `--virtual` demo runs both emulators on one host over a veth pair
(`acccs_secc ↔ acccs_evcc`, with link-local addresses `fe80::1` / `fe80::2`).
Create it with:

```bash
sudo ./setup_veth.sh
```

This is also a prerequisite for the conformance tests.

### 5. Smoke test

With steps 1–4 done, run the stock SECC and EVCC in two terminals. The
emulators bind raw sockets, so they need root (`sudo`) or the `cap_net_raw`
capability.

Note the `sudo "$(which python)"` form: `sudo` resets `PATH` to its
`secure_path`, so a plain `sudo python` runs the *system* interpreter, which
lacks the dependencies you installed into the conda/venv environment from
step 2 (you'd hit `ModuleNotFoundError: No module named 'nmap'`). The
command substitution resolves to the activated environment's interpreter
*before* `sudo` runs, so the env's Python is used:

```bash
# Terminal 1
sudo "$(which python)" run_secc.py --config default-secc --virtual

# Terminal 2 (a second or two later)
sudo "$(which python)" run_evcc.py --config default-evcc --virtual
```

A clean session walks through these milestones:

```
SLAC → SDP/TLS → SessionSetup → ServiceDiscovery → PowerDelivery →
CurrentDemand loop → PowerDelivery → WeldingDetection → SessionStop
```

ending with the EVCC logging `Going to state A`. If you see that, your setup is
complete. See [Running the emulators](#running-the-emulators) for personality
and CLI-override details.

## Running the emulators

> **New here?** Complete [Project Setup](#project-setup) first — it covers the
> submodule clone, dependencies, PKI certificates, and the veth pair that the
> commands below assume are already in place.

Only two scripts are expected to be run from command line: ```run_evcc.py``` and ```run_secc.py```. The other scripts and files serve as tools and utilities for these scripts to run.

Both scripts take an optional `--config <personality.yaml>` flag and an
optional `--runtime <runtime.yaml>`. When `--config` is omitted, each
script defaults to its per-role DIN device file (`run_secc.py` →
`din_dc_extended-secc`, `run_evcc.py` → `din_dc_extended-evcc`). Stock personalities live in the
[`personalities/`](personalities/) directory; the bundled defaults are a
complete materialised dump of every field with its built-in value:

The emulators bind raw sockets, so they need root (`sudo`) or the
`cap_net_raw` capability. Use the `sudo "$(which python)"` form so the
activated environment's interpreter is used — a plain `sudo python` resets
`PATH` to `secure_path` and runs the *system* interpreter, which lacks your
installed dependencies (see [Project Setup → Smoke test](#5-smoke-test) for
the full explanation):

```bash
# Run the stock virtual SECC and EVCC over the acccs_secc/acccs_evcc veth pair
sudo ./setup_veth.sh
sudo "$(which python)" run_secc.py --config default-secc --virtual
sudo "$(which python)" run_evcc.py --config default-evcc --virtual
```

Personality search order (per [ADR-0001](docs/adr/0001-personality-yaml-config.md)):

1. explicit `--config <path>` (file path);
2. `personalities/<name>.yaml` in the repo;
3. `~/.acccs/personalities/<name>.yaml` (user-local).

### CLI overrides

Personality fields are **not** CLI-overridable — they describe *who* the
emulated device is, and changing them mid-experiment is a different
personality. Operational knobs are overridable:

| Flag | Overrides |
|---|---|
| `--log-level <LEVEL>` | `runtime.log.console_level` |
| `--file-log-level <LEVEL>` | `runtime.log.file_level` |
| `--virtual` | `runtime.virtual` |
| `--nmap` | `runtime.nmap.enabled` |
| `--nmap-args <ARGS>` | `runtime.nmap.args` |
| `--nmap-ports <SPEC>` | `runtime.nmap.ports` |
| `--source-port <PORT>` | `runtime.source_port` |
| `--modified-cordset` | `runtime.modified_cordset` (SECC only) |

To customise a personality, copy `personalities/default-<role>.yaml` to a
new file and edit. The Pydantic loader validates strictly — unknown keys
are a hard error. See [`docs/personality-authoring.md`](docs/personality-authoring.md)
for a section-by-section authoring guide and the bundled example library.

## Certificate Management

Basic TLS certificate generation for the demo is covered in
[Project Setup](#project-setup) step 3. This section provides the deeper
Plug-and-Charge context and the contract-certificate workflow.

### Plug and Charge (ISO 15118-2 and ISO 15118-20)
For Plug and Charge, certificates and private keys have to be created at the beginning. Go to the [pki](/app/shared/pki) directory and run the ```create_certs.sh``` script like this:
```bash
./create_certs.sh -v iso-2
```
or
```bash
./create_certs.sh -v iso-20
```
If you are running it for the first time, you may have to change the permission to be able to exceute it. In this case, do this:
```bash
chmod 755 create_certs.sh
```