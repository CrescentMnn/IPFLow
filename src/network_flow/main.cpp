#include <iostream>
#include <IPv4Layer.h>
#include <Packet.h>
#include <PcapFileDevice.h>

struct ThresholdConfig {
    //DDoS thresh
    uint32_t packets_ps = 10000;
    uint32_t max_packet_size = 100;
    uint32_t flow_time = 1;

    //Port scan
    uint32_t unique_ports = 100;
    uint32_t scan_time = 60;
    double scan_packets_pp = 3.0;

    //General
    uint32_t min_normal_packet_size = 64;
    uint32_t max_normal_packet_size = 1518;
    double min_flow_duration = 0.1;
    double max_flow_duration = 3600;
}

enum class TransportProtocol : uint8_t{
    TCP;
    UDP;
    ICMP;
    OTHER;
}

struct flow{
    pcpp::IPv4Address srcIP;
    TransportProtocol protocol;
    uint16_t srcPort;
    uint16_t dstPort;

    //packet stats
    uint64_t packet_count;
    uint64_t byte_count;
    //timestamps
    double first_seen;
    double lasst_seen;
}

int check_threshold(const std::unique_ptr<pcpp::IFileReaderDevice> &reader){
   pcpp::RawPacket rawPacket;
   
   while(reader->getNextPacket(rawPacket)){
	pcapp::Packet parsedPacket(&rawPacket);
        if(parsedPacket.isPacketOfType(pcpp::IPv4)){
	    pcpp::IPv4Address srcIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address();
	    pcpp::IPv4Address dstIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address();

	    if(parsedPacket.isOfType(pcpp::TCP)){
	    }
	    if(parsedPacket.isOfType(pcpp::UDP)){
	    }
	    if(parsedPacket.isOfType(pcpp::ICMP)){
	    }
	}
   }

}

int main(){
   
    std::unique_ptr<pcpp::IFileReaderDevice> reader(pcpp::IFileReaderDevice::getReader("test.pcap"));
    if(reader == nullptr){
        std::cerr << "Error determining the pcap file" << std::endl;
	return 1;
    }

    if(!reader->open()){
        std::cerr << "Error opening file..." << std::endl;
	return 1;
    }

    if(!reader->setFilter("net 192.168.1.114")){
        std::cerr << "Error applying filter..." << std::endl;
	return 1;
    }

    pcpp::RawPacket rawPacket;

    while(reader->getNextPacket(rawPacket)){
        pcapWriter.writePacket(rawPacket);
        pcpp::Packet parsedPacket(&rawPacket);
    }

    reader->close();

    return 0;
}
