#include <iostream>
#include <cstddef>
#include <unordered_map>
#include <IPv4Layer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <IcmpLayer.h>
#include <Packet.h>
#include <PcapFileDevice.h>

#include "hash_functions.h"

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

struct flow_seq{
    pcpp::IPv4Address srcIP;
    pcpp::IPv4Address dstIP;
    TransportProtocol protocol;
    uint16_t srcPort;
    uint16_t dstPort;

    //packet stats
    uint64_t packet_count;
    uint64_t byte_count;
    //timestamps
    double first_seen;
    double last_seen;
}

//this will make the flow
struct map_val{
    pcpp::IPv4Address srcIP;
    pcpp::IPv4Address dstIP;
    uint16_t srcPort;
    uint16_t dstPort;
    TransportProtocol protocol;
}

//apply hash for hash key
size_t create_key(const map_val& values){
    std::string srcIP = values.srcIP.toString();
    std::string dstIP = values.dstIP.toString();

    uint8_t protocol = static_cast<uint8_t>(values.protocol);

    auto srcIPHash = hash_function(srcIP);
    auto dstIPHash = hash_function(dstIP);
    auto srcPortHash = hash_function(values.srcPort);
    auto dstPortHash = hash_function(values.dstPort);
    auto protocolHash = hash_function(protocol);

   return srcIPHash ^ (dstIPHash << 1) ^ (srcPortHash << 2) ^ (dstPortHash << 3) ^ protocolHash; 
}

flow_seq check_flow(const std::unique_ptr<pcpp::IFileReaderDevice> &reader){
   pcpp::RawPacket rawPacket;
   flow_seq flow;

   //will add flow parameters here
   while(reader->getNextPacket(rawPacket)){
	pcapp::Packet parsedPacket(&rawPacket);
        if(parsedPacket.isPacketOfType(pcpp::IPv4)){
	    pcpp::IPv4Address srcIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address();
	    flow.srcIP = srcIP;
	    pcpp::IPv4Address dstIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address();
	    flow.dstIP = dstIP;

	    if(parsedPacket.isOfType(pcpp::TCP)){
	        flow.protocol = 0;
		auto* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
		if(tcpLayer == nullptr){
		    std::cerr << "Something went wrong with TCP layer..." << std::endl; return 1;
		}
		flow.srcPort = tcpLayer.getSrcPort();
		flow.dstPort = tcpLayer.getDstPort();
	    }else if(parsedPacket.isOfType(pcpp::UDP)){
		flow.protocol = 1;
		auto* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
		if(udpLayer == nullptr){
		    std::cerr << "Something went wrong with UDP layer..." << std::endl; return 1;
		}
		flow.srcPort = udpLayer.getSrcPort();
		flow.dstPort = udpLayer.getDstPort();
	    }else if(parsedPacket.isOfType(pcpp::ICMP)){
		flow.protocol = 2;
		auto* icmpLayer = parsedPacket.getLayerOfType<pcpp::IcmpLayer>();
		if(icmpLayer == nullptr){
		    std::cerr << "Something went wrong with ICMP layer..." << std::endl; return 1;
		}
                flow.srcPort = 0;
		flow.dstPort = 0;
    		//maybe ICMP object is unnecesary to this
	    }else{
	        flow.protocol = 3;
	    }

	    auto rawPacket = parsedPacket.getRawPacket();
	    flow.first_seen = rawPacket.getPacketTimeStamp();
	    flow.byte_count += rawPacket.getRawDataLen();
	    flow.packet_count++;
	}
    }
    return flow;
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
