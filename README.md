# liquidfiles.py

`liquidfiles.py` is a command-line utility to work with [LiquidFiles](https://www.liquidfiles.com/) servers for sending files, listing messages, creating filelinks, etc.

It is a Python implementation of [liquidfiles_unix](https://github.com/liquidfiles/liquidfiles_unix).

## Requirements

* Python >= 3
* [requests](https://github.com/psf/requests) >= 2.6

## Installation

Simply download the `liquidfiles.py` script to your desired location. Alternatively, you can build a `.whl` and install it with `pip`.

```console
python3 -m build
pip install dist/*.whl
```

## Usage

`liquidfiles.py` uses sub-commands to interact with your LiquidFiles server.

```console
liquidfiles.py -s https://liquidfiles.example.com -k ${API_KEY} <sub-command> <options>
```

The current supported sub-commands are:

* __attach__: upload given files and returns the ids
* __config__: manage configuration
* __delete-attachments__: deletes the given attachments
* __delete-filelink__: deletes the given filelink
* __filelink__: creates filelink for the given files
* __filelinks__: list available filelinks
* __file-request__: send file(s) to specified user
* __messages__: list available messages
* __send__: send file(s) to specified user
* __version__: show version information

To get a sub-command's detailed description, options and usage, use the `-h` or `--help` option.

```console
liquidfiles.py <sub-command> --help
```

## Config File

To avoid having to use the `-s` and `-k` options on every command, you can use a config file to set your server and API key.

`liquidfiles.py` checks the following files for your server and API key:

1. `$HOME/.liquidfiles.conf`
2. `/usr/local/etc/liquidfiles.conf`
3. `/etc/liquidfiles.conf`

The config file uses standard INI format with a `[config]` section.

```ini
[config]
api_key = ${API_KEY}
server = https://liquidfiles.example.com
```

The `config` sub-command can be used to configure `~/.liquidfiles.conf` for the current user.

```console
liquidfiles.py config --set-server https://liquidfiles.example.com --set-api-key ${API_KEY}
```
