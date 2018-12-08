# CSE 5473 Project -- ARP Poisoning
Group: Aaron Fuhrer, Jim Dickson, Zach McGohan,  Adam Tetzlaff

### Description
This project is the course project for CSE 5473. The goal of the project was to produce a program that could perform ARP poisoning. The program was tested using a setup of multiple Ubuntu virtual machines. One virtual machine was setup as an attack virtual machine and three others were setup as victim machines. Each virtual machine was assigned a static IP address and the defualt gateway IP address was used. The project was ran using Python 2.7.

### Installation
- Install Python 2.7
- Install the python package `scapy` using a command like: `pip install scapy`
- Clone the repo

### How to use
- Navigate to the `/src` directory
- Run the ARP poisoning program using the command: `sudo python poison.py`
- The program will start to scan for MAC addresses
- Once the available MAC addresses are found, you can choose which MAC/IP addresses you want to attack
- After your choices are made, the program will start to ARP poison each selection
- You can kill the program using `ctrl-c` which will unpoison each victim's ARP table before the program exits

### Documentation
The source code is well commented and should be easy to follow.

### Demo link
[Link to a demo on YouTube](https://youtu.be/iJPuBdXMJCU)

### Extras
Inside the `/src` directory the `poison-win.py` is Windows implementation of the project. The documentation on how to use it can be found in `poison-win-readme.txt`.
