# py-rfid
A quick python script to utilize a cheap CTX 203-ID-RW

I've had in my possession for quite a while one of these cheap Chinese CTX 203-ID-RW reader/writers for RFID tags.  I never made use of it because, like with most
Chinese goods, it came with no documentation.  There was some Windows software that came with it.  But that was it.  It also came with several key fobs.  When I finally
got back to this stuff, it was for a different reason than I had originally.  I looked around at the software and found several C examples but no python.  At least not
until I ran across a set of code.  It was cobbled together from some very rudimentary reverse engineering.  When I disassembled the Windows software, it did start to
compare with this software.  I eventually got enough understanding to know what I actually had and wrote a simple python 3.0 script that seems to do better than the
original.  I'm not sure the original code even worked, but this works well enough to read the tags that I had and let me find out that the reader I had isn't capable
enough to do what I originally wanted.  The code is far from complete, but maybe someone will get some use out of it.
