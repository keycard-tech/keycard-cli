# keycard-cli

`keycard` is a command line tool to manage [Status Keycards](https://github.com/keycard-tech/status-keycard).

* [Dependencies](#dependencies)
* [Installation](#installation)
* [Continuous Integration](#continuous-integration)
* CLI Commands
  * [Card info](#card-info)
  * [Keycard applet installation](#keycard-applet-installation)
  * [Card initialization](#card-initialization)
  * [Deleting the applet](#deleting-the-applet)
  * [Keycard shell](#keycard-shell)

## Dependencies

* An USB smart card reader (those with contacts are more reliable than NFC readers).
* On linux you need to install and run the [pcsc daemon](https://linux.die.net/man/8/pcscd).

## Installation

Download the binary for your platform from the [releases page](https://github.com/keycard-tech/keycard-cli/releases) and rename the file to `keycard`, removing the platform specific suffix.

## Continuous Integration

Jenkins builds provide:

* [PR Builds](https://ci.status.im/job/status-keycard/job/prs/job/keycard-cli/) - Run only the `test` and `build` targets.
* [Manual Builds](https://ci.status.im/job/status-keycard/job/keycard-cli/) - Create GitHub release draft with binaries for 3 platforms.

Successful PR builds are mandatory.

## Usage

### Card info

```bash
keycard info -l debug
```

The `info` command will print something like this:

```
Installed: true
Initialized: false
InstanceUID: 0x
PublicKey: 0x112233...
Version: 0x
AvailableSlots: 0x
KeyUID: 0x
```
### Keycard applet installation

The `install` command will install an applet to the card.
You can download the status `cap` file from the [keycard-tech/status-keycard releases page](https://github.com/keycard-tech/status-keycard/releases).

```bash
keycard install -l debug -a PATH_TO_CAP_FILE
```

In case the applet is already installed and you want to force a new installation you can pass the `-f` flag.


### Card initialization


```bash
keycard init -l debug
```

The `init` command initializes the card and generates the secrets needed to pair the card to a device.

```
PIN 123456
PUK 123456789012
Pairing password: RandomPairingPassword
```

### Deleting the applet

:warning: **WARNING! This command will remove the applet and all the keys from the card.** :warning:

```bash
keycard-cli delete -l debug
```

### Keycard shell
Check the `_shell-commands-examples` folder.
