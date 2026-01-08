#include <iostream>
#include <IPv4Layer.h>
#include <Packet.h>
#include <PcapFileDevice.h>

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

    // will be written to it
    pcpp::PcapFileWriterDevice pcapWriter("output.pcap", pcpp::LINKTYPE_ETHERNET);
    
    if(!pcapWriter.open()){
        std::cerr << "Cannot open file for writing.." << std::endl;
	return 1;
    }

    if(!reader->setFilter("net 192.168.1.114")){
        std::cerr << "Error applying filter..." << std::endl;
	return 1;
    }

    pcpp::RawPacket rawPacket;
    //if(!reader.getNextPacket(rawPacket)){
    //    std::cerr << "Couldnt read the first packet in file" << std::endl;
    //	return 1;
    //}

    while(reader->getNextPacket(rawPacket)){
        pcapWriter.writePacket(rawPacket);
        pcpp::Packet parsedPacket(&rawPacket);

        if(parsedPacket.isPacketOfType(pcpp::IPv4)){
            pcpp::IPv4Address srcIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address();
	    pcpp::IPv4Address dstIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address();

	    std::cout << "Source IP is: " << srcIP << "\nDestination IP is: " << dstIP << std::endl;
        }
    }

    reader->close();

    return 0;
}
