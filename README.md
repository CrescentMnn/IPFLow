# IPFLow

IPFLow is a project integrating Machine Learning, Cybersecurity, and Networking. Its goal is to provide an **Anomaly-based IDS** that monitors network traffic, detecting significant spikes or changes to identify potential attacks and vulnerabilities.

It is aimed to build a simple automatic packet capture and analysis workflow with the use of ML to analyse the packets being recieved and the network flow metrics in order to detect a possible attack or unusual activity in a network, this will be done by analysing the following metrics:

//TODO METRICS:


## Overall project structure

The object of this project (as mentioned before) is to provide a Machine Learning approach to a simple IDS in my local network, this will be achieved by using c++ for the packet capture (using PcapPlusPlus) and python for the analysis and training of the model (still not defined).

This project will use a HIDS (Host Intrusion Detection System) architecture, given hardware limitations and simplicity this type of architecture is the most fitting for the project.

> Note that this project structure is *subject to change* as this is only the first draft

## Project phases

This project will be done in 2 different phases, each are aimed to improve the project so it can achieve its full purpose:

**Phase 1: Offline analysis**

This phase consists of reading and parsing the packets, which will be stored in a *pcap* file and then analysed using the ML architecture we preciously disscused, this architecture will be trained on already made and tested datasets.

This will help me outline the process of the analysis and capture of packets, as well as helping me build and tune the model that will be used.

**Phase 2: Live analysis**

The second phase is aimed to be the final phase of the project, migrating from offline reading and analysing to real time capture and analysis (thus real time detection and alerting of threats will follow), using the foundations built on phase one this will help my project be more structured and developed, decreasing the chances of system breaking errors and majoir security flaws (overlook of important data).

This means that my project will achieve two different goals, the first one will be that of a *forensic analysis* software, and the second one will be the true *IDS* deployement.

**Phase 3 (optional): Hybrid Deployment**

The third phase (which is still not confirmed) will aim to add *Signature-based* rules to the already established *Anomaly-based IDS*, making this system a *Hybrid Intrusion Detection System*, reflecting real world security systems, where Signature-based systems help prevent already known attack more precisely, while Anomaly-based IDS systems are better to detect unknown attacks, the use of both of these is what an optimal security strategy would make use of.

## Packet capture

As stated before this project will make use of the PcapPlusPlus C++ library, which [can be found here](https://pcapplusplus.github.io/), PcapPlusPlus is a powerful C++ framework built on top of the libpcap library, making the parsing of packets easier, it uses the PCAP file extension and it will allow us to read and write to these types of files, which will be stored in my databse and analysed accordingly.

See more on *PCAP* files used in libpcap [here](https://wiki.wireshark.org/Development/LibpcapFileFormat)

## Machine learning

## Project flow 

The following is an outline of how the basic process for this project will look:

Packet capture
   ↓
Packet parsing
   ↓
Feature extraction
   ↓
Flow aggregation
   ↓
Anomaly detection
   ↓
Alert generation

