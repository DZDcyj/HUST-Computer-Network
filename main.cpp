#include "mainwindow.h"
#include <QApplication>
#include <QDebug>


void test() {
	pcap_if_t *alldevs;
	pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (-1 == pcap_findalldevs(&alldevs, errbuf)) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return;
    }
    int i = 0;
    for (d = alldevs; d; d = d->next) {
		qDebug() << ++i << d->name;
		if (d->description) {
			qDebug() << d->description;
		} else {
			qDebug() << " (No description available)\n";
		}
    }
    if (0 == i) {
		qDebug() << "\nNo interfaces found! Make sure WinPcap is installed." <<
				 Qt::endl;
        return;
    }
	qDebug() << "\nEnter the interface number(1 - " << i << "): ";
}

int main(int argc, char *argv[]) {
    QApplication a(argc, argv);
	MainWindow   w;
    w.show();
	test();
    return a.exec();
}
