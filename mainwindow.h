#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QListWidgetItem>
#include "IPScannerController.h"

namespace Ui {
	class MainWindow;
}

static const int LISTENING = 0;
static const int READY = 1;
static const int REFRESHING = 2;

class MainWindow : public QMainWindow {
	Q_OBJECT

public:

	explicit MainWindow(QWidget *parent = nullptr);
	~MainWindow();
	void initializeTable();

private slots:
	void on_RefreshDeviceButton_clicked();

	void refreshDeviceList();

	void on_StopListenButton_clicked();

	void on_StartListenButton_clicked();

	void on_WebDevices_currentRowChanged(int currentRow);

	void refreshIPPackageList(long ip);

	void changeState(int state);

	void on_ClearIPPackages_clicked();

	void on_QuitButton_clicked();

signals:
	void refreshWebDevices();

	void sendState(int state);

private:

	Ui::MainWindow *ui;
};

#endif // MAINWINDOW_H
