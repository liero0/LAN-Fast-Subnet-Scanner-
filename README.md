# LAN-Fast-Subnet-Scanner-
Fast Subnet and Vendor Scanner. This application is a custom, standalone administrative utility built for local network auditing and host discovery within a controlled environment. It scans local IPv4 subnets to inventory connected hardware, determine response latency, and pull local hostnames/MAC vendor prefixes. 

Low-Level Network Calls: Uses P/Invoke (iphlpapi.dll - SendARP) to discover devices on the local Layer-2 segment that have ICMP/ping blocked by host firewalls.Parallel Port & NetBIOS Probing: Queries local UDP Port 137 (NetBIOS) and standard DNS/LLMNR endpoints concurrently across local subnet ranges (/24) to resolve machine names.Single-File Executable: It is a newly compiled, self-contained binary built locally for administrative use, which lacks a public code-signing certificate and prior cloud reputation history.

Use this in Windows to compile the executable:
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /target:winexe /win32icon:"eth.ico" /out:LAN-Fast-Subnet-Scanner.exe LAN-Fast-Subnet-Scanner.cs
