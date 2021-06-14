#ifndef IPSCANNERCONTROLLER_H
#define IPSCANNERCONTROLLER_H

#include <QObject>
#include <QApplication>
#include <WinSock2.h>
#include "pcap.h"
#include "pcap-stdinc.h"
#include <vector>
#include <iostream>
#include <string>
#include <QMap>
#include <functional>
#include <QThread>
#include <QDebug>
#include <QPointer>
#include <QStandardItemModel>
#include <sstream>
#include <bitset>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

using std::vector;

class IPScannerController : public QObject {
	Q_OBJECT

private:

	static IPScannerController *m_instance;
	IPScannerController() {}

	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	vector<pcap_if_t *>devices;
	unsigned int size = 0;

public:

	static IPScannerController *getInstance() {
		return m_instance;
	}

	unsigned int         getDeviceCount()const;

	char                *getErrorBuffer();

	pcap_if_t           *getDevice(unsigned int order);

	vector<pcap_if_t *> &getDevices();

	void                 refreshDevices();
};

void GetIPString(uint32_t ip,
				 char    *ipAddress);

struct frameheader {
	BYTE DstMac[6];
	BYTE SrcMac[6];
	BYTE FrameType;
};

using FrameHeader = struct frameheader;

struct ip_header {
	BYTE  version;
	BYTE  service_type;
	WORD  total_length;
	WORD  identification;
	WORD  flags;
	BYTE  ttl;
	BYTE  protocol;
	WORD  crc;
	DWORD source_address;
	DWORD dest_address;
	DWORD options;

	friend std::ostream &operator<<(std::ostream           &os,
									const struct ip_header &ih) {
		os << "version: " << ih.version << std::endl;
		os << "total_length: " << ih.total_length << std::endl;
		os << "identification: " << ih.identification << std::endl;
		os << "flags: " << ih.flags << std::endl;
		os << "ttl: " << ih.ttl << std::endl;
		os << "protocol: " << ih.protocol << std::endl;
		os << "crc: " << ih.crc << std::endl;
		char source_ipaddr[16], dest_ipaddr[16];
		GetIPString(ih.source_address, source_ipaddr);
		GetIPString(ih.dest_address,   dest_ipaddr);
		os << "Source Address: " << source_ipaddr << std::endl;
		os << "Destination Address: " << dest_ipaddr << std::endl;
		return os;
	}
};

using IPHeader = struct ip_header;

struct data {
	FrameHeader *frameheader;
	IPHeader    *ipheader;
};

using Data = struct data;

class IPNode : public QObject {
	Q_OBJECT

private:

	long _IPAddress;
	long _IPPackageCount;
	Data *_Data;

public:

	IPNode(IPNode &) = delete;
	IPNode(const IPNode &) = delete;
	IPNode &operator=(const IPNode &) = delete;

	explicit IPNode(long sourceIP) : _IPAddress(sourceIP), _IPPackageCount(1) {}

	inline void addCount() {
		_IPPackageCount++;
	}

	inline long getPackageCount() const {
		return _IPPackageCount;
	}

	inline long getIPAddress() const {
		return _IPAddress;
	}

	inline void addData(Data *data) {
		_Data = data;
	}

	inline Data *getData() const {
		return _Data;
	}
};


class IPNodeManager : public QObject {
	Q_OBJECT

private:

	QMap<long, IPNode *>ipnodes;
	static IPNodeManager *m_instance;
	IPNodeManager() {}

public:

	static IPNodeManager *getInstance() {
		return m_instance;
	}

	IPNodeManager(const IPNodeManager &) = delete;
	IPNodeManager(IPNodeManager &) = delete;
	IPNodeManager        &operator=(const IPNodeManager &) = delete;

	void                  addNode(long sourceIp);

	void                  addData(long  sourceIp,
								  Data *header);

	void                  clear();

	QMap<long, IPNode *> &getIPNodes();
};

class IPListener : public QObject {
	Q_OBJECT

private:

	static IPListener *m_instance;
	QStandardItemModel *m_model;
	QStandardItemModel *stat_model;
	IPListener() {}

	pcap_if_t *currDevice;
	pcap_t *descriptor;
	IPNodeManager *manager;
	bool running_status = false;
	char errbuf[PCAP_ERRBUF_SIZE];
	const char *packet_filter = "ip";
	int net_mask;
	struct bpf_program fcode;
	struct pcap_pkthdr *header;
	const unsigned char *pkt_data;
	int device_index;
	bool initialized = false;

private:

	void initialize() {
		descriptor = pcap_open_live(currDevice->name,
									1000,
									1,
									1000,
									errbuf);
		if (descriptor == nullptr) {
			throw std::runtime_error("Unable to open the adapter");
		}
		net_mask = 0xffffff;
		if (currDevice->addresses != nullptr) {
			net_mask =
				((sockaddr_in *)(currDevice->addresses->netmask))->sin_addr.S_un.
				S_addr;
		}
		if (pcap_compile(descriptor, &fcode, packet_filter, device_index,
						 net_mask) < 0) {
			throw std::runtime_error(
				"Unable to compile the packet filter. Check the syntax.");
		}
		if (pcap_setfilter(descriptor, &fcode) < 0) {
			throw std::runtime_error("Error setting the filter");
		}
		reloadManager();
		initialized = true;
	}

	void reloadManager() {
		manager = IPNodeManager::getInstance();
		manager->clear();
	}

public:

	static IPListener *getInstance() {
		return m_instance;
	}

	void setListeningDevice(pcap_if_t *device, int deviceIndex) {
		currDevice = device;
		device_index = deviceIndex;
		initialize();
	}

	void bindTableModel(QStandardItemModel *model) {
		this->m_model = model;
	}

	void bindStatsModel(QStandardItemModel *model) {
		this->stat_model = model;
	}

	void changeState() {
		running_status = !running_status;
	}

signals:

	void resultUpdated(long ip);
	void listenstopped();

public slots:

	void start() {
		running_status = true;
	}

	void stop() {
		running_status = false;
	}

	Data *parseProtocol(const unsigned char *pkg) {
		IPHeader *ih = (IPHeader *)(pkg + 14);
		FrameHeader *fh = (FrameHeader *)pkg;
		Data *data = new Data;
		data->frameheader = fh;
		qDebug() << "Dest Mac: " << fh->DstMac << "Source Mac: " << fh->SrcMac <<
				 "FrameType: " << fh->FrameType << Qt::endl;
		data->ipheader = ih;
		qDebug() << "Version: " << ih->version << "Service Type: " <<
				 ih->service_type << "Total Length: " << ih->total_length << Qt::endl;
		qDebug() << "Identification: " << ih->identification << "Flags: " <<
				 ih->flags << Qt::endl;
		qDebug() << "TTL: " << ih->ttl << "Protocol: " << ih->protocol <<
				 "crc: " << ih->crc << Qt::endl;
		char src_addr[16], dst_addr[16];
		GetIPString(ih->source_address, src_addr);
		GetIPString(ih->dest_address,   dst_addr);
		qDebug() << "Source Address: " << src_addr << "Dest Address: " <<
				 dst_addr << Qt::endl;
		qDebug() << "Options: " << ih->options << Qt::endl;
		return data;
	}

	std::string word2Str(BYTE *words) {
		std::stringstream stream;
		for (int i = 0; i < 6; ++i) {
			stream << std::hex << static_cast<int>(words[i]);
		}
		auto result = std::string(stream.str());
		result = "0x" + result;
		return result;
	}

	std::string getProtocol(BYTE protocol) {
		switch (protocol) {
			case 6:
				return "TCP";
			case 17:
				return "UDP";
			default:
				return "Other";
		}
	}

	std::string getEthernetType(WORD EthernetType) {
		int head = EthernetType & 0x0f;
		int tail =  EthernetType >> 4;
		if (head == 8) {
			switch (tail) {
				case 0:
					return "IPv4";
				case 6:
					return "ARP";
				case 0xdd:
					return "IPv6";
			}
		} else if ((head == 0x81) && (tail == 0)) {
			return "IEEE 802.1Q";
		}
		return "Other";
	}

	std::string getCRCBits(WORD crc) {
		return std::bitset<16>(crc).to_string() + "(" + std::to_string(crc) + ")";
	}

	void splitVersion(BYTE version, std::vector<std::string> &res) {
		if (res.size() < 2) {
			res.resize(2);
		}
		res[0] = std::to_string((version >> 4));
		res[1] = std::to_string((version & 0x0f));
	}

	void splitService(BYTE service,std::vector<std::string>&res){
		if (res.size() < 2) {
			res.resize(2);
		}
		res[0] = std::to_string(service>>2);
		res[1] = std::to_string(service&0x03);
	}

	void addItems(QStandardItemModel               *_model,
				  std::initializer_list<std::string>components) {
		int row = _model->rowCount();
		int i = 0;
		for (auto it = components.begin(); it != components.end(); ++it) {
			_model->setItem(row,
							i++,
							new QStandardItem((*it).c_str()));
		}
	}

	void splitFlag(WORD flags,std::vector<std::string>&res){
		if (res.size() < 2) {
			res.resize(2);
		}
		res[0] = std::bitset<3>(flags>>3).to_string() + "(" +std::to_string(flags>>13)+ ")";
		res[1] = std::bitset<13>(flags&0x1fff).to_string()+"("+std::to_string(flags&0x1fff)+")";
	}

	void addInfoToStats(Data *data) {
		auto dst_mac = word2Str(data->frameheader->DstMac);
		auto src_mac = word2Str(data->frameheader->SrcMac);
		char src_addr[16], dst_addr[16];
		GetIPString(data->ipheader->source_address, src_addr);
		GetIPString(data->ipheader->dest_address,   dst_addr);
		std::vector<std::string> header_info,service_info,flag_info;
		splitVersion(data->ipheader->version, header_info);
		splitService(data->ipheader->service_type,service_info);
		splitFlag(data->ipheader->flags,flag_info);
		addItems(stat_model, {
			dst_mac, src_mac, getEthernetType(
				data->frameheader->FrameType), header_info[0],
			header_info[1], service_info[0],service_info[1],
			std::to_string(data->ipheader->total_length),
			std::to_string(data->ipheader->identification),
			flag_info[0],flag_info[1],
			std::to_string(data->ipheader->ttl),
			getProtocol(data->ipheader->protocol), getCRCBits(
				data->ipheader->crc), src_addr, dst_addr,
			std::to_string(data->ipheader->options)
		});
	}

	void running() {
		running_status = true;
		int result;
		while ((result = pcap_next_ex(descriptor, &header, &pkt_data)) >= 0) {
			if (!running_status) {
				break;
			}
			QThread::msleep(10);
			if (result == 0) {
				continue;
			}
			Data *data = parseProtocol(pkt_data);
			IPHeader *ih;
			ih = data->ipheader;
			manager->addNode(ih->source_address);
			manager->addData(ih->source_address, data);
			// Update table (Not recommend)
			int  rows = m_model->rowCount();
			bool updated = false;
			char src_addr[16];
			GetIPString(ih->source_address, src_addr);
			for (int i = 0; i < rows; ++i) {
				auto item = m_model->item(i, 0);
				auto curr_ip = item->text();
				if (curr_ip != src_addr) {
					continue;
				}
				auto count = m_model->item(i, 1)->text();
				long count_long = count.toLong() + 1;
				delete m_model->item(i, 1);
				m_model->setItem(i, 1,
								 new QStandardItem(std::to_string(count_long).
												   c_str()));
				updated = true;
				break;
			}
			if (!updated) {
				m_model->setItem(rows, 0, new QStandardItem(src_addr));
				m_model->setItem(rows, 1,
								 new QStandardItem(std::to_string(1).c_str()));
			}
			addInfoToStats(data);
			emit resultUpdated(ih->source_address);
		}
		emit listenstopped();
	}
};

class IPListenerController : public QObject {
	Q_OBJECT

public:

	IPListenerController() {
		m_listener = IPListener::getInstance();
		m_listener->moveToThread(&m_listenerThread);
		connect(this,
				&IPListenerController::listenStart,
				m_listener,
				&IPListener::running);
		connect(this,
				&IPListenerController::listenStop,
				m_listener,
				&IPListener::stop);
		connect(this,
				&IPListenerController::listenStart,
				m_listener,
				&IPListener::start);
		connect(m_listener,
				&IPListener::listenstopped,
				this,
				&IPListenerController::threadStopped);
	}

	static IPListenerController *getInstance() {
		return m_instance;
	}

	~IPListenerController() {
		m_listenerThread.quit();
		m_listenerThread.wait();
	}

	void start() {
		m_listenerThread.start();
		emit listenStart();
	}

	void stop() {
		m_listenerThread.terminate();
		emit listenStop();
	}

signals:

	void listenStart();
	void listenStop();

public slots:

	void threadStopped() {}

private:

	QThread m_listenerThread;
	IPListener *m_listener;
	static IPListenerController *m_instance;
};

#endif // IPSCANNERCONTROLLER_H
