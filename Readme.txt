# Project: Tor-NonTor Realistic Dataset Generation

In this project we created a realistic dataset where we have tor traffic and non-tor traffic. We capture the traffic by using Wireshark.  We build a flow-based ML pipeline to detect Tor activity by extracting statistical features from network traffic and evaluating by multiple ML model. 


To ensure realistic and noise-free data collection, we created an isolated VirtualBox-based testbed. The testbed consists of

> Oracle VirtualBox - Version 7.1.6 

> Whonix Gateway + Workstation for Tor traffic generation- Below shared the OS Configuration 


 ,g$$P"     """Y$$.".        OS: Debian GNU/Linux 12 (bookworm) x86_64 
 ,$$P'              `$$$.     Host: VirtualBox 1.2 
',$$P       ,ggs.     `$$b:   Kernel: 6.1.0-28-amd64 
`d$$'     ,$P"'   .    $$$    Uptime: 6 mins 
 $$P      d$'     ,    $$P    Packages: 1032 (dpkg) 
 $$:      $$.   -    ,d$$'    Shell: zsh 5.9 
 $$;      Y$b._   _,d$P'      Resolution: 1920x978 
 Y$$.    `.`"Y$$$$P"'         DE: Xfce 4.18 
 `$$b      "-.__              WM: Xfwm4 
  `Y$$                        WM Theme: Arc 
   `Y$$.                      Theme: Arc [GTK2], Adwaita [GTK3] 
     `$$b.                    Icons: Arc [GTK2], Adwaita [GTK3] 
       `Y$$b.                 Terminal: xfce4-terminal 
          `"Y$b._             Terminal Font: Monospace 12 
              `"""            CPU: Intel i5-10400 (3) @ 2.904GHz 
                              GPU: 00:02.0 VMware SVGA II Adapter 
                              Memory: 573MiB / 1210MiB 

> Debian-based  for Non-Tor traffic generation - Below shared the OS Configuration


    ,g$$$$$$$$$$$$$$$P.       ---------- 
  ,g$$P"     """Y$$.".        OS: Debian GNU/Linux 12 (bookworm) x86_64 
 ,$$P'              `$$$.     Host: VirtualBox 1.2 
',$$P       ,ggs.     `$$b:   Kernel: 6.1.0-40-amd64 
`d$$'     ,$P"'   .    $$$    Uptime: 2 mins 
 $$P      d$'     ,    $$P    Packages: 1714 (dpkg) 
 $$:      $$.   -    ,d$$'    Shell: bash 5.2.15 
 $$;      Y$b._   _,d$P'      Resolution: 1920x966 
 Y$$.    `.`"Y$$$$P"'         DE: GNOME 43.9 
 `$$b      "-.__              WM: Mutter 
  `Y$$                        WM Theme: Adwaita 
   `Y$$.                      Theme: Adwaita [GTK2/3] 
     `$$b.                    Icons: Adwaita [GTK2/3] 
       `Y$$b.                 Terminal: gnome-terminal 
          `"Y$b._             CPU: Intel i5-10400 (2) @ 2.904GHz 
              `"""            GPU: 00:02.0 VMware SVGA II Adapter 
                              Memory: 1180MiB / 7492MiB 




Network Configuration : We have two type of dataset one is tor and another is non tor. When we create tor traffic we develop a dedicated Ethernet cable to get tor network traffic. On the other hand we have also a dedicated Ethernet cable for direct internet connection. So, First of all we need to install Whonix-gateway and Debian-base Workstation.

After that in Debian-base Workstation we need to follow below step-

> Click Debian WorkStation
> Go to Settings
> Click Network
> Adopter 1 used for NAT
> Adopter 2 used for Attached to: Internet Network, Name: Whonix
> Ok

After that run the Debian-based Workstation and follow the below steps-

> search network setting
> In network Setting there is two Ethernet cable Connection Ethernet(enp0s3,enp0s8)
> So, In our project we used enpOs3 used for Non-Tor Connection and enp0s8  used for Tor Connection

Now we setup first Non-Tor Connection (enp0s3):
> Click Setting
> Click IPv4
> IPv4 Method- click Automatic (DHCP)
> DNS- Click Automatic 
> Routes - Click Automatic 
> Apply


After that we setup Tor Connection (enp08)
> Click Setting
> Click IPv4
> IPv4 Method- click Manual
> Addresses- Address- 10.152.152.14, Netmask- 255.255.192.0, Gateway- 10.152.152.10
> DNS- 10.152.152.10
> Routes- Address- 10.152.152.14, Netmask- 255.255.192.0, Gateway- 10.152.152.10


N.B- Here we use address 10.152.152.10  Which is comes from Whonix gateway. 


Now We can check the Connection. For connection check we used this link https://check.torproject.org/

For non tor connection we click wired connection from settings and Turn on enp0s3 and on that time turn off enp0s8 wired connection. After that we used above link and it shows Sorry. You are not using Tor.

For Tor connection we click wired connection from settings and Turn on enp0s8 and on that time turn off enp0s3 wired connection and need to run whonix gateway machine. After that we used above link and it shows Congratulations. This browser is configured to use Tor. 

Disable UDP Connection :

Before start the capture or data collection we need to disable the UDP protocol. Here I describe the step by step process how to disable the UDP protocol.

- Go to terminal in Debian Workstation
-sudo apt install ufw -y
sudo ufw reset
 
# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing
 
# Allow DNS only
sudo ufw allow out 53/udp
sudo ufw allow in 53/udp
 
# Block ALL UDP traffic except DNS
sudo ufw deny out proto udp from any to any port 1:52
sudo ufw deny out proto udp from any to any port 54:65535

# Allow essential TCP services
sudo ufw allow in 22/tcp   # SSH
sudo ufw allow in 80/tcp   # HTTP
sudo ufw allow in 443/tcp  # HTTPS
 
# Enable firewall
sudo ufw enable
sudo ufw status numbered


Dataset Overview: To generate the dataset we capture different type of traffic from different type of application. Such as Web Browsing, Video Streaming, File Transfer, Video Conference, VOIP, Instant Message. For Web Browsing and Video Streaming we used Selenium Web Driver which allows us to write scripts in Python that can open websites, click buttons, fill forms, and interact with web elements just like a real user. We used chrome browser for browsing and streaming. 


 
Script Details: 

In our project to generate the traffic we write some python script. Bellow I shared the script details.
--------------------------------------------------------------------
1. Web Browsing Dataset:

> Browsing_Distraction_Free_Server.py (Run this script for 1hr in both connection)- create 2 pcap file
There is two mode to run this script one is generate and another one is reuse. In the beginning we run the script in tor connection and use generate mode. In this mode there is a text file created which called sequence file. It creates the sequence of Browsing for example: This creates this type of URL...

http://54.224.244.197/?size=1318,14  That means we browse this URL http://54.224.244.197/ , size=1318 means there is randomly created 1318 character in that website and the size of the page going to be 1318 Bytes and then wait 14 seconds before the next request.

Similarly when I run this script in Non-Tor connection I change the configuration. On that time I run this script in Reuse Mode.

> Browsing_Wekepedia.py (Run this script for 1hr in both connection)- Create 2 pcap file 
There is also two mode to run this script one is generate and another one is reuse. In the beginning we run the script in tor connection and use generate mode. In this mode there is a text file created which called sequence file. It creates the sequence of Browsing for example: This creates this type of URL...

https://en.wikipedia.org/wiki/English_language,13 That means we browse this url https://en.wikipedia.org/wiki/English_language and then wait 13 seconds before the next request.

---------------------------------------------------------------------

2. Video Streaming Dataset:
> Video_Streaming_Distraction-Free_Server_Youtube.py (Run this script for 1hr in both connection)- create 16 pcap file

In this part we are streaming the videos in two platform one is Youtube and another one is Distraction-Free_Server. The videos are uploaded in those platform by resolution such as 240p,420p,1080p and random. We are streaming the videos from my own youtube channel. 

This videos are created by myself and converted into different resolution. After that I uploaded it my youtube channel.

Same Videos we uploaded in Distraction-Free_Server. So, we also streaming that videos from this platform.


So, When we run this script, there is a part of configuration to change the mode. Here we use same concept (generate/reuse) which I used for Browsing and we also need to change the platform (Youtube/ Distraction-Free_Server) before run the script. When we run this script the video streaming sequences are generated in text file. Here is the example of sequences..

http://54.224.244.197/view.php?filename=Video+3+240p+%5BibS0NwSTBpo%5D.mp4,291  It means http://54.224.244.197/view.php?filename=Video+3+240p+%5BibS0NwSTBpo%5D.mp4 this is the URL link of the video which one is playing and this video are streaming 291 seconds.

-----------------------------------------------------------------

3. File Transfer:
> File_Transfer_Distraction-Free_Server.py (Run this script for 1hr in both connection)- create 8 pcap file

There is also two mode to run this script one is generate and another one is reuse. This two modes are using same purpose which i describe in Web Browsing and Video Streaming Dataset. In this part we downloaded different type of files such as 10MB, 50MB, 100 MB and Random files. So We need to change the parameter before run the script. When we run the script file download sequences  are wrote in the text file. Such as...

random_10MB_1759772677.dat,15  It means 10MB file downloaded and 15 sec wait to download another file. 
--------------------------------------------------------------------

4. Video Conference:
> To create this dataset I talked with my friend via MS Teams Video Call and collect the traffic, One for used tor connection and another for used Non-Tor Connection and capture this traffic by using Wireshark. (Video conference time 1 hr in both connection) - create 2 pcap file
------------------------------------------------------------------------
5. VoIP:
> To create this dataset I talked with my friend via MS Teams Audio Call and collect the traffic, One for used tor connection and another for used Non-Tor Connection and capture this traffic by using Wireshark. (Audio conference time 1 hr in both connection) - create 2 pcap file
------------------------------------------------------------------------

6. Instant Messaging:
> To create this dataset I chat with my friend via Micsoft Teams  and collect the traffic, One for used tor connection and another for used Non-Tor Connection and capture this traffic by using wireshark. In this case I chat with my manually. (Chatting duration 1 hr in both connection) - create 2 pcap file
-------------------------------------------------------------------------

After generating pcap files I converted those pcap files to csv files for getting the flow. For this I wrote a python script by using scapy. The name of that script is  Scapy_Flow_Generation.py . We got  51 flow features.  To run this script at first we need to use the exact path for folder and run this command in the terminal :

> python Scapy_Flow_Generation.py input.pcap output.csv






Finally we run this script - Analysis.ipynb for testing the model accuracy and classify tor and non-tor traffic.  




