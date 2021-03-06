FireSync
========

This project is meant to be an as-small-as-possible completely
standalone server that replaces Firefox Accounts and Firefox Sync 1.5
services, allowing for completely self-hosted sync without
a single connection to Mozilla servers.

Caveat emptor
-------------

This project is currently **cannot be considered secure**.
Do **not** use this for anything you need real security for.
If you or someone you know can audit this - I'd appreciate it.

Some, but not all known security issues:

1. Login page is server over the network and is prone to malicious adversary
   injecting JS or spoofing HTML to leak your password. That said, the server
   cannot be trusted to have "zero-knowledge".

   This issue can only be fixed by Mozilla.

   Current FireSync implementation *intentionally* sends password
   *in plaintext* (still *using TLS*, but plaintext *inside*) over the network.
   Better not rely on JS crypto, it'd only give a false sense of security.

2. PyBrowserID library has broken RSA implementation that's silently used
   if M2Crypto (or PyCryptodome as its drop-in replacement) is not available.
   There's a hack in `settings.py` that forcibly prevents PyBrowserID from
   even trying to work if M2Crypto is missing, but if you're embedding this
   into some existing project, you should be aware of this issue.

3. The whole Mozilla Services system is a complicated mess (in my personal
   opinion). The particular issue is that documentation about how those
   things are used is scarce in some areas - the general picture
   is relatively well explained, but the devil's in the details,
   and they're not always here.
   
   So I just cannot vouch my implementation is correct. It *seems* to work
   *at the moment*, but that's all I can tell. But I can also tell that I've
   suspended and resumed this project a few times, and every single time
   I got back to my code, something that had worked before was broken.
   So I can't think of this as anything but fragile.
   
What (hopefully) works
----------------------

- Firefox Accounts service implementation. One can log in.

- Token Server also works. Not in a way it does on "real" Mozilla
  services, but it issues tokens that are understood by our
  Sync service and that should be enough, at least for starters.
  
- Some parts of Sync service are here. I was able to get two
  Firefox instances sync with each other, although there were
  some occasional problems (e.g. not seeing other browser's updates)
  that I haven't debugged yet.

- Profiles return username, email address and a static picture.
  This uses very primitive OAuth2 token server implementation
  that's not suitable for storing any really private data.
  So, be sure to read the source code about the limitations.

What doesn't (TODO)
-------------------

- Sync implementation is incomplete.

- Profile editing is not implemented.

- Signing up. Currently you have to use Django admin
  (or `createsuperuser` command) for this.

- This project needs an extensive test suite that can be ran both
  against the official servers and this implementation.


License
-------

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but *without any warranty*; without even the implied warranty of
*merchantability* or *fitness for a particular purpose*.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

User profile icon (janus/static/profile.png) was made by CreativeTail.com
and is licensed under the Creative Commons Attribution 4.0
International (CC BY 4.0) license. More information about this license
can be found at <https://creativecommons.org/licenses/by/4.0/>.
Actual PNG file was downloaded from Wikimedia Commons website.
