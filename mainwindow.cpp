#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QtConcurrent/QtConcurrent>
#include <QStandardItemModel>

QStandardItemModel*model;
QStandardItemModel*stats_model;

MainWindow::MainWindow(QWidget *parent) :
	QMainWindow(parent),
	ui(new Ui::MainWindow) {
	ui->setupUi(this);
	initializeTable();
	connect(this,&MainWindow::sendState,this,&MainWindow::changeState);
	connect(IPListener::getInstance(),&IPListener::resultUpdated,this,&MainWindow::refreshIPPackageList);
}

MainWindow::~MainWindow() {
	delete ui;
}

void addHeaderLabels(QStandardItemModel*model, std::initializer_list<std::string> headers){
	QStringList headerLabels;
	for(auto it = headers.begin();it != headers.end();++it){
		headerLabels<<((*it).c_str());
	}
	model->setHorizontalHeaderLabels(headerLabels);
}

void initializeTableWithHeaders(QTableView *table,QStandardItemModel**model,std::initializer_list<std::string>headers){
	table->horizontalHeader()->setDefaultAlignment(Qt::AlignCenter);
	table->horizontalHeader()->setSectionResizeMode(QHeaderView::Fixed);
	*model = new QStandardItemModel();
	addHeaderLabels(*model,headers);
	table->setModel(*model);
}

void MainWindow::initializeTable() {
	QTableView *table = ui->IPHeaders;
	initializeTableWithHeaders(table,&model,{"Source IP", "Package Count"});
	IPListener::getInstance()->bindTableModel(model);
	QTableView* stats = ui->PackageStats;
	initializeTableWithHeaders(stats,&stats_model,{"Dest Mac","Source Mac","FrameType","Version","Header Length","Differentiated Services","ECN","Total Length","Identification","Flags","Offset","TTL","Protocol","Header Checksum","Source Address","Dest Address","Options"});
	IPListener::getInstance()->bindStatsModel(stats_model);
}

void MainWindow::on_RefreshDeviceButton_clicked() {
	refreshDeviceList();
	emit sendState(REFRESHING);
}

void outputOneLineDebugInfo(const char* info){
	qDebug()<<info<<Qt::endl;
}

void MainWindow::refreshDeviceList() {
	outputOneLineDebugInfo("Entered");
	auto deviceList = ui->WebDevices;
	outputOneLineDebugInfo("Chosen");
	QFutureWatcher<void> *pWatcher = new QFutureWatcher<void>(this);
	outputOneLineDebugInfo("watcher ok");
	auto instance = IPScannerController::getInstance();
	outputOneLineDebugInfo("instance ok");
	deviceList->blockSignals(true);
	deviceList->clear();
	deviceList->blockSignals(false);
	outputOneLineDebugInfo("clear ok");
	deviceList->addItem("Refreshing...");
	outputOneLineDebugInfo("Cleared");
	QFuture<void> future = QtConcurrent::run([ = ]() {
		outputOneLineDebugInfo("Refreshing");
		instance->refreshDevices();
		outputOneLineDebugInfo("Refreshed");
	});
	connect(pWatcher, &QFutureWatcher<void>::finished, this, [ = ]() {
		outputOneLineDebugInfo("Refresh Completed");
		deviceList->blockSignals(true);
		deviceList->clear();
		deviceList->blockSignals(false);
		auto devices = instance->getDevices();
		for(auto &device : devices) {
			std::string item = device->name;
			if(device->description) {
				item += " (";
				item += device->description;
				item += ")";
			} else {
				item += " (No Description Available)";
			}
			deviceList->addItem(item.c_str());
		}
		outputOneLineDebugInfo("List Updated");
	});
	pWatcher->setFuture(future);
}

void MainWindow::on_StopListenButton_clicked() {
	emit sendState(READY);
	IPListenerController::getInstance()->stop();
}


void MainWindow::on_StartListenButton_clicked() {
	emit sendState(LISTENING);
	IPListenerController::getInstance()->start();
}

void MainWindow::refreshIPPackageList(long ip){

}

void MainWindow::changeState(int state){
	switch(state){
	case LISTENING:
		ui->StartListenButton->setEnabled(false);
		ui->StopListenButton->setEnabled(true);
		ui->WebDevices->setEnabled(false);
		ui->RefreshDeviceButton->setEnabled(false);
		break;
	case READY:
		ui->StartListenButton->setEnabled(true);
		ui->StopListenButton->setEnabled(false);
		ui->WebDevices->setEnabled(true);
		ui->RefreshDeviceButton->setEnabled(true);
		break;
	case REFRESHING:
		ui->StartListenButton->setEnabled(false);
		ui->StopListenButton->setEnabled(false);
		ui->WebDevices->setEnabled(true);
		break;
	default:break;
	}
}


void MainWindow::on_WebDevices_currentRowChanged(int currentRow){
	auto instance = IPScannerController::getInstance();
	auto device = instance->getDevice(currentRow+1);
	IPListener::getInstance()->setListeningDevice(device,currentRow+1);
	IPListener::getInstance()->bindTableModel(model);
	qDebug()<<device->name<<Qt::endl;
	ui->StartListenButton->setEnabled(true);
}



void MainWindow::on_ClearIPPackages_clicked()
{
	model->removeRows(0,model->rowCount());
	stats_model->removeRows(0,stats_model->rowCount());
}


void MainWindow::on_QuitButton_clicked()
{
	qApp->quit();
}

