# IPFLow

IPFLow is a project integrating Machine Learning, Cybersecurity, and Networking. Its goal is to provide an **anomaly based IDS** (or *AIDS*) that monitors network traffic, detecting significant spikes or changes to identify potential attacks and vulnerabilities.

It is aimed to build a simple automatic packet capture and analysis workflow with the use of ML to analyse the packets being recieved and the network flow metrics in order to detect a possible attack or unusual activity in a network, this will be done by analysing the following metrics:

//TODO METRICS:


## Overall project structure

The object of this project (as mentioned before) is to provide a Machine Learning approach to a simple IDS in my local network, this will be achieved by using c++ for the packet capture (using PcapPlusPlus) and python for the analysis and training of the model (still not defined).

> Note that this project structure is *subject to change* as this is only the first draft

## Project phases

This project will be done in 2 different phases, each are aimed to improve the project so it can achieve its full purpose:

**Phase 1: Offline analysis**

This phase consists of reading and parsing the packets, which will be stored in a *pcap* file and then analysed using the ML architecture we preciously disscused, this architecture will be trained on already made and tested datasets.

This will help me outline the process of the analysis and capture of packets, as well as helping me build and tune the model that will be used.

**Phase 2: Live analysis**

The second phase is aimed to be the final phase of the project, migrating from offline reading and analysing to real time capture and analysis (thus real time detection and prevention of threats will follow), using the foundations built on phase one this will help my project be more structured and developed, decreasing the chances of system breaking errors and majoir security flaws (overlook of important data).

This means that my project will achieve two different goals, the first one will be that of a *forensic analysis* software, and the second one will be the true *IDS* deployement.

## Packet capture

## Machine learning
