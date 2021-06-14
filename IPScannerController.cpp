#include "IPScannerController.h"

IPScannerController *IPScannerController::m_instance = new IPScannerController;
IPListener *IPListener::m_instance = new IPListener;
IPNodeManager* IPNodeManager::m_instance = new IPNodeManager;
IPListenerController *IPListenerController::m_instance = new IPListenerController;


void IPScannerController::refreshDevices() {
	int res = pcap_findalldevs(&alldevs, errbuf);
	if (-1 == res) {
		return;
	}
	size = 0;
	for (auto *curr = alldevs; curr != nullptr; curr = curr->next) {
		size++;
	}
	devices.clear();
	devices.resize(size);
	int i = 0;
	for (auto *curr = alldevs; curr != nullptr; curr = curr->next) {
		devices[i++] = curr;
	}
}

vector<pcap_if_t *> &IPScannerController::getDevices() {
	return devices;
}

pcap_if_t *IPScannerController::getDevice(unsigned int order) {
	if (order > devices.size()) {
		return nullptr;
	}
	return devices.at(order - 1);
}

unsigned int IPScannerController::getDeviceCount()const {
	return size;
}

char *IPScannerController::getErrorBuffer() {
	return errbuf;
}

void GetIPString(uint32_t ip, char *ipAddress) {
	const int NBYTES = 4;
	uint8_t octet[NBYTES];
	for(int i = 0; i < NBYTES; ++i) {
		octet[i] = ip >> (i * 8);
	}
	sprintf(ipAddress, "%d.%d.%d.%d", octet[3], octet[2], octet[1], octet[0]);
}

void IPNodeManager::addNode(long sourceIp) {
	auto iter = ipnodes.find(sourceIp);
	if(iter != ipnodes.end()) {
		// Got it
		IPNode *node = iter.value();
		node->addCount();
		return;
	}
	// Not hit
	IPNode *curr = new IPNode(sourceIp);
	ipnodes[sourceIp] = curr;
}

void IPNodeManager::addData(long sourceIp, Data* data) {
	auto iter = ipnodes.find(sourceIp);
	if(iter != ipnodes.end()) {
		// Got it
		IPNode *node = iter.value();
		node->addData(data);
		return;
	}
	// Not hit
	IPNode *curr = new IPNode(sourceIp);
	curr->addData(data);
	ipnodes[sourceIp] = curr;
}

QMap<long, IPNode*>&IPNodeManager::getIPNodes() {
	return ipnodes;
}

void IPNodeManager::clear() {
	if(!ipnodes.empty()){
		ipnodes.clear();
	}
}
