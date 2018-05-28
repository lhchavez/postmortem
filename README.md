# Postmortem

A tiny gdb frontend/wrapper that shows stack, registers, source, and control
flow graph. This is intended for post-mortem debugging.

## Usage

```shell
./postmortem.py [--gdb-path=/usr/bin/gdb] -- <gdb arguments>
```

## Screenshot

![Screenshot](https://raw.github.com/lhchavez/postmortem/master/screenshot.png)

## License

BSD 3-Clause License. See `LICENSE` for details.
