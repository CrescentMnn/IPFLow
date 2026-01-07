#include <iostream>
#include <IPv4Layer.h>
#include <Packet.h>
#include <PcapFileDevice.h>

int main(){
    
    pcpp::PcapFileReaderDevice reader("test.pcap");
    if(!reader.open()){
        std::cerr << "Error opening the pcap file" << std::endl;
	return 1;
    }

    pcpp::RawPacket rawPacket;
    if(!reader.getNextPacket(rawPacket)){
        std::cerr << "Couldnt read the first packet in file" << std::endl;
	return 1;
    }

    pcpp::Packet parsedPacket(&rawPacket);

    if(parsedPacket.isPacketOfType(pcpp::IPv4)){
        pcpp::IPv4Address srcIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address();
	pcpp::IPv4Address dstIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address();

	std::cout << "Source IP is: " << srcIP << "\nDestination IP is: " << dstIP << std::endl;
    }

    reader.close();

    return 0;
}
