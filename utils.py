#!/usr/bin/env python
"""
Utility methods.
Copyleft 2011 Ian Gallagher <crash@neg9.org>
Some methods taken directly, or with modification from the Scapy project
(http://www.secdev.org/projects/scapy) - noted accordingly
"""

from textwrap import TextWrapper
from terminal import TerminalController

def color_string(data, color):
    # Setup a TerminalController for formatted output
    term = TerminalController()

    result = term.render("${" + color.upper() + "}" + data + "${NORMAL}")
    return(result)

def sane(x):
    """
    From Scapy's utils.py
    """
    r=""
    for i in x:
        j = ord(i)
        if (j < 32) or (j >= 127):
            r=r+"."
        else:
            r=r+i
    return ' '.join((r[:8], r[8:])).strip()

def indent(data, spaces):
    return '\n'.join(map(lambda x: ' ' * spaces + x, data.split('\n')))

def hexdump(x, indent=False):
    """
    From Scapy's utils.py, modified to return a string instead of print directly,
    and just use sane() instead of sane_color()
    """
    result = ""

    x=str(x)
    l = len(x)
    i = 0
    while i < l:
        result += "%08x  " % i
        for j in range(16):
            if i+j < l:
                result += "%02x " % ord(x[i+j])
            else:
                result += "   "
            if j%16 == 7:
                result += " "
        result += "  "
        result += sane(x[i:i+16]) + "\n"
        i += 16

    if indent:
        """
        Print hexdump indented 4 spaces, and blue - same as Wireshark
        """
        indent_count = 4 # Same as Wireshark's hex display for following TCP streams
        tw = TextWrapper(width = 78 + indent_count, initial_indent = ' ' * indent_count, subsequent_indent = ' ' * indent_count)

        result = tw.fill(result)
        result = color_string(result, "CYAN")

        return(result)
    else:
        """
        Print hexdump left aligned, and red - same as Wireshark
        """
        result = color_string(result.strip(), "RED")
        return(result)

if __name__ == "__main__":
    import os

    print(hexdump('\xff'*68))
    print(hexdump('\x41'*61, indent=True))

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
