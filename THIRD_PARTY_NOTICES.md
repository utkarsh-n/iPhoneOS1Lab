# Third-party source notices

The patches modify QEMU and the devos50 S5L8900 work at upstream commit `501c85c4f8a3503965e38d5d4f30a02c4bc9171c`. QEMU is distributed under the GNU GPL version 2, subject to each file's existing license header. The corresponding GPL text is in `LICENSES/QEMU-GPL-2.0.txt`. Obtain the exact upstream source and retain its existing headers when applying these patches: https://github.com/devos50/qemu/tree/501c85c4f8a3503965e38d5d4f30a02c4bc9171c

`tools/extract_firmware.py` identifies planetbeing/xpwn format references and declares GPL-3.0-or-later. `LICENSES/XPWN-GPL-3.0.txt` is the license text obtained from https://github.com/planetbeing/xpwn/blob/master/LICENSE. The LZSS algorithm provenance is documented in that source file. No Apple firmware or firmware decryption key is included.

The adapted NOR generator implementation was omitted because its upstream checkout did not provide a declared license. Its provenance remains in `SOURCES.md` for research reference. Its wrapper explicitly reports the omission.

These notices describe the named upstream components and derivatives. They do not impose or invent a blanket license on other user-authored source. Dependency and firmware provenance do not grant ownership of third-party artifacts.
