I always try to think about how I might get something done by leveraging WMI, since it's usually always on and available. When I read that somebody had beat me to the punch I decided to start writing a powershell implementation. Once I polish it up a bit more I'll write a better README for it, but here's the first rough hack at it.

The primary focus of this PowerShell tool is to stealthily provide a decent remote-shell on hosts than only have port 135 open by uploading the vbScript and interacting with it via WMI. Command outputs are base64 encoded and written to WMI namespaces, then retrieved using WMI and decoded locally. 

Here's a link to Andrei Dumitrescu's presentation on the topic, for reference, and his original scripts if you're working from Linux: http://www.lexsi.com/Windows-Management-Instrumentation-Shell.html

Future Planned Capabilities:
- I also have a vbScript for Hex encoding, but I need to fix some things for it to work as well as the base64 script.
- - I'll be polishing up the functionality, adding file-upload capability, and trying to make it pass-the-hash.
