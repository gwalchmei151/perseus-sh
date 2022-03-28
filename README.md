## _C2 Course - SOC Project_  

More Info: https://www.centreforcybersecurity.com/programmes

_Objective:
Create a script that runs different cyber attacks in a given network to check if monitoring alerts appear_

_Functions:_
_- Install relevant applications on the computer_
_- Execute network scans and attacks_
_- Save into a log all of the activities executed by code_

# Perseus.sh
A script that examines the network to find machines, and gives the user the option to use nmap or masscan, and then execute a variety of attacks on the target. Two versions - one for those that haven't made lolcat executable from PATH

## When script starts
Check if executed by Root user, otherwise issue reminder and quit:
![img1](./images/img1.png)

Check if perseus_logs  folder exists in /var/log. If it doesn’t create it.
![img2](./images/img2.png)

Then proceed to welcome screen

![img3](./images/img3.png)

Check for missing programmes and ask for permission to install:

![img4](./images/img4.png)

## Scan Phase

Into main script after installation of missing programmes

![img5](./images/img5.png)

OR into main script without installation if necessary programmes present

![img6](./images/img6.png)

Scanning message

![img7](./images/img7.png)

Enumerate Hosts on network and generate list to choose target OR Enter target manually.
Then choose desired scan method - nmap or masscan.

![img8](./images/img8.png)

## Masscan
Choose first and last ports to set range

![img9](./images/img9.png)

Discovered ports will be listed and programme will ask for follow-up action

![img10](./images/img10.png)

## Nmap
Script will automatically ``` nmap -A``` the target

![img11](./images/img11.png)

Discovered information (ports, protocols, services, and versions) will be displayed to the user

![img12](./images/img12.png)

## Brute Force SSH

### Through Masscan

![img13](./images/img13.png)

List successfull credentials and exit

![img14](./images/img14.png)

### Through Nmap

![img15](./images/img15.png)

## Kerberos Enum (msfconsole)

### Through Nmap

![img16](./images/img16.png)

Enter information to create msfconsole resource file

![img17](./images/img17.png)

Example msfconsole output

![img18](./images/img18.png)

### Kerberos service not detected, manual port entry (for example if masscan is used instead of nmap):

![img19](./images/img19.png)

Kerberos not detected since masscan did not do service detection. Enter other information as per usual. The rest of the results are the same as above . 

![img20](./images/img20.png)

## Man in the Middle

The MitM attack in this is meant to be an Arp Spoof, but that only works on my computer due to the need for custom .pyarp spoofer

The script gets the ip of the target and the ip of the gateway automatically.

## MSF Venom Payload Creation

Select Victim OS (nmap scan recommended for more info):

![img21](./images/img21.png)

Select Stager, name file, select target port:

![img22](./images/img22.png)

RC file is built and MSF Console is launched:

![img23](./images/img23.png)

MSF Console using RC file to set options and run exploit/multi/handler

![img24](./images/img24.png)

exploit/multi/handler session begun:

![img25](./images/img25.png)

## Generated Log Samples

Nmap into MSF console Kerberos Enumusers

![img26](./images/img26.png)

Masscan into Brute Force SSH (Hydra)

![img27](./images/img27.png)

Masscan into MitM:

![img28](./images/img28.png)

Masscan into MSFVenom and then console:

![img29](./images/img29.png)

Nmap into MSFVenom then console

![img30](./images/img30.png)
