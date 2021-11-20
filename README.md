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
