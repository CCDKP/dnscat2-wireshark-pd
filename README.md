This is a PostDissector for Wireshark to read unencrypted DNSCat 2 traffic.
Based off the dnscat dissector by DiabloHorn https://diablohorn.wordpress.com

It's not pretty, and my first stab at LUA, but it seems to work with wireshark 3.0.1 and it found the CTF flag
It currently is limited to ascii-decoding commands, but could be expanded to decode session IDs and more.

Invoke with: wireshark -Xlua_script:dnscat.lua
