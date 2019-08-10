TCPHound
======================

TCPHound is a free Win32 utility for auditing TCP connections. I decided to develop TCPHound because existing utilities out there are unable to meet my needs. TCPHound has 2 unique features.

1.   **TCPHound provides data logging.** Most utilities provide only real-time output. Once connections are closed, they are removed from the list. Hence, you would have to stare at the screen continuously. With TCPHound, I can start the utility and come back 2 hours later to scroll through the logs. 
2.   **TCPHound tracks connection duration.** Connection duration is an important indicator of the type of traffic. A short connection might indicate a malware phoning home. A long connection with high outbound traffic might indicate data theft. A long connection with bursty traffic might indicate a C&C channel. TCPHound can also resolve the organization which owns the IP, hence allowing you to quickly identify suspicious connections.

![image](https://limbenjamin.com/media/tcphound.png)
  
![image](https://limbenjamin.com/media/tcphound2.png)

Downloads
=========

[TCPHound v1.3 64bit](https://limbenjamin.com/files/TCPHound/TCPHound_v1.3_x64.exe) - SHA1() = a8f5acc6a156cd57fdfab648ffb7d7a41be99220  
[TCPHound v1.3 32bit](https://limbenjamin.com/files/TCPHound/TCPHound_v1.3_x86.exe) - SHA1() = 0cbcf4f78b9ea2750fbf52da7ff85fd4cffc8ef8  

Due to a limitation in the GetModuleBaseName WINAPI, running the 32bit version on a 64bit machine will result in wrong or missing process names. Hence, please use the 64bit version on a 64bit machine.


Q&A
===
  
  
Why not Wireshark?
------------------
Wireshark is a great tool if you know what you are looking for. Otherwise, you are looking for a needle in a haystack. TCPHound complements Wireshark by allowing you to identify suspicious connections. You can then filter your Wireshark captures and view traffic originating from only that specific IP address. Furthermore, TCPHound provides connection-to-process mapping, allowing you to identify the application that is generating that traffic.

How does the AS info query work?
---------------------------------
TCP hound uses a self hosted web API to resolve the Autonomous System which supposedly owns the IP range (Hence, you might see TCPHound's own connection in the logs). So as not to accidentally disclose internal IP addresses, you would need to right click on the entry to manually trigger the IP resolution. Furthermore, we do not want to resolve the connection that is used to resolve the connection that is used to resolve the connection... You get the idea.  

Why display both image name and full path?
------------------------------------------
Image name is a quick way to determine the process owning the connection. However, full path is also important, we want to make sure that it is `C:\windows\explorer.exe` and not `C:\Users\user\explorer.exe`.

Can I have the source code?
---------------------------
The utility is closed source at this point in time. If I decide to open source it in future, I will update this page.

License?
--------
The software is distributed "as is". No warranty of any kind is expressed or implied. You use at your own risk. The author will not be liable for data loss, damages, loss of profits or any other kind of loss while using or misusing this software.

The Licensee is allowed to freely redistribute the software subject to the following conditions.  
1.	The Software may be installed and Used by the Licensee for any legal purpose.
2.	The Licensee will not charge money or fees for the software product, except to cover distribution costs.  
3.  The Licensor retains all copyrights and other proprietary rights in and to the Software.  
4.	Use within the scope of this License is free of charge and no royalty or licensing fees shall be paid by the Licensee.  

Bugs or comments?
-----------------
Create an issue on [github](https://github.com/limbenjamin/TCPHound)

Changelog
---------

v1.3 (28/07/19) - Fixed bug with stale process data. Added ability to monitor SYN_SENT state.  
v1.2 (14/01/17) - Fixed bug with csv export. Self host IP to ASN mapping API. Added SHA1 hash functionality.  
v1.1 (17/12/16) - Added export to file functionality.  
v1.0 (11/12/16) - Initial Release.  
  
