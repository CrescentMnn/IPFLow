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
};

enum class TransportProtocol : uint8_t{
    TCP,
    UDP,
    ICMP,
    OTHER
};

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
};

//this will make the flow
struct map_val{
    pcpp::IPv4Address srcIP;
    pcpp::IPv4Address dstIP;
    uint16_t srcPort;
    uint16_t dstPort;
    TransportProtocol protocol;
};

//hash map constructors
struct MapValHash{
    size_t operator()(const map_val& values) const{
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
};

struct MapValEqual{
    bool operator()(const map_val& lhs, const map_val& rhs) const{
        return lhs.srcIP == rhs.srcIP && lhs.dstIP == rhs.dstIP && lhs.srcPort == rhs.srcPort && lhs.dstPort == rhs.dstPort && lhs.protocol == rhs.protocol;
    }
};

//create hash map || DHOULD DELETE AND DECLARE WHERE NEEDED
std::unordered_map create_map(){
    return std::unordered_map<map_val, flow_seq, MapValHash, MapValEqual>;
}

void check_flow(const std::unique_ptr<pcpp::IFileReaderDevice> &reader, std::unordered_map<map_val, flow_seq, MapValHash, MapValEqual>& flow_map){
   pcpp::RawPacket rawPacket;

   //read while there are packets
   while(reader->getNextPacket(rawPacket)){
	pcpp::Packet parsedPacket(&rawPacket);
	
	map_val new_tuple;
	//check if IPv4 (for now, IPv6 too later)
        if(parsedPacket.isPacketOfType(pcpp::IPv4)){
	    pcpp::IPv4Address srcIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address();
	    new_tuple.srcIP = srcIP;

	    pcpp::IPv4Address dstIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address();
	    new_tuple.dstIP = dstIP;
	    
	    //check transport protocol
	    if(parsedPacket.isOfType(pcpp::TCP)){
		new_tuple.protocol = TransportProtocol::TCP;
		auto* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
		if(tcpLayer == nullptr){
		    std::cerr << "Something went wrong with TCP layer..." << std::endl; return;
		}
		new_tuple.srcPort = tcpLayer.getSrcPort();
		new_tuple.dstPort = tcpLayer.getDstPort();
	    }else if(parsedPacket.isOfType(pcpp::UDP)){
		new_tuple.protocol = TransportProtocol::UDP;
		auto* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
		auto* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
		if(udpLayer == nullptr){
		    std::cerr << "Something went wrong with UDP layer..." << std::endl; return;
		}
		new_tuple.srcPort = udpLayer.getSrcPort();
		new_tuple.dstPort = udpLayer.getDstPort();
	    }else if(parsedPacket.isOfType(pcpp::ICMP)){
		new_tuple.protocol = TransportProtocol::ICMP;
		auto* icmpLayer = parsedPacket.getLayerOfType<pcpp::IcmpLayer>();
		if(icmpLayer == nullptr){
		    std::cerr << "Something went wrong with ICMP layer..." << std::endl; return;
		}
		new_tuple.srcPort = 0;
		new_tuple.dstPort = 0;
    		//maybe ICMP object is unnecesary to this
	    }else{
	        new_tuple.protocol = TransportProtocol::OTHER;
	    }
	    
 	    //check map for stats
            auto item = flow_map.find(new_tuple);

	    if(item != flow_map.end()){
	        //FOUND VALUE
		item->second.packet_count++;
		item->second.byte_count+=rawPacket.getRawDataLen();
		//TODO: parse timespec into double value
		item->second.last_seen=rawPacket.getPacketTimeStamp();
	    }else{
	        //NOT FOUND
                flow_seq new_flow = { 
			new_tuple.srcIP,
			new_tuple.dstIP,
			new_tuple.protocol,
			new_tuple.srcPort,
			new_tuple.dstPort,
			1,
			rawPacket.getRawDataLen(),
			rawPacket.getPacketTimeStamp(),
			rawPacket.getPacketTimeStamp()
		};
		flow_map[new_tuple] = new_flow;
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
    
    //create map and pass it to fn
    std::unordered_map<map_val, flow_seq, MapValHash, MapValEqual> flow_map;
    pcpp::RawPacket rawPacket;

    while(reader->getNextPacket(rawPacket)){
        pcapWriter.writePacket(rawPacket);
        pcpp::Packet parsedPacket(&rawPacket);
    }

    reader->close();

    return 0;
}
