import sys
import traceback
import os
from PyQt5 import QtWidgets, uic, QtCore, QtGui
from lib import attack, bluekeep
from time import sleep

# CONSTANTS
polling_interval = 3
ui_file = "lib/interface.ui"
icon_file = "lib/icon.png"

# For debug purposes since pyQT does not display exception details
sys._excepthook = sys.excepthook


def custom_exception_hook(exctype, value, tracebk):
    print(exctype, value, tracebk)
    sys._excepthook(exctype, value, tracebk)
    sys.exit(1)


sys.excepthook = custom_exception_hook


# Thread execution
class WorkerSignals(QtCore.QObject):
    finished = QtCore.pyqtSignal()
    error = QtCore.pyqtSignal(tuple)
    result = QtCore.pyqtSignal(object)
    progress = QtCore.pyqtSignal(int)


class Worker(QtCore.QRunnable):
    def __init__(self, fn, *args):
        super(Worker, self).__init__()
        self.fn = fn
        self.args = args
        self.signals = WorkerSignals()

    @QtCore.pyqtSlot()
    def run(self):
        try:
            result = self.fn(*self.args)
        except:
            traceback.print_exc()
            exctype, value = sys.exc_info()[:2]
            self.signals.error.emit((exctype, value, traceback.format_exc()))
        else:
            self.signals.result.emit(result)  # Return the result of the processing
        finally:
            self.signals.finished.emit()  # Done


# GUI
class Ui(QtWidgets.QFrame):
    def show_log(self, message):
        self.log_browser.insertPlainText(message)

    def get_plc_ip(self):
        return str(self.spinbox_ip_1_1.value()) + '.' + str(self.spinbox_ip_1_2.value()) + '.' + str(
            self.spinbox_ip_1_3.value()) + '.' + str(self.spinbox_ip_1_4.value())

    def get_hmi_ip(self):
        return str(self.spinbox_ip_2_1.value()) + '.' + str(self.spinbox_ip_2_2.value()) + '.' + str(
            self.spinbox_ip_2_3.value()) + '.' + str(self.spinbox_ip_2_4.value())

    def ping(self, ip):
        if os.system("ping -n 1 -w 1 " + ip) == 0:
            self.hmi_online = True
            return "Online"
        else:
            self.hmi_online = False
            return "Offline"
        self.buttons_enable(True)

    def print_output(self, message):
        self.show_log(message)

    def buttons_enable(self, status):
        for button in self.buttons_plc:
            eval("self." + button + ".setEnabled(" + str(status & self.plc_online & ~self.scan_running) + ")")
        for button in self.buttons_hmi:
            eval("self." + button + ".setEnabled(" + str(status & self.hmi_online & ~self.scan_running) + ")")

    def thread_complete(self):
        self.show_log("...[DONE]\n\n")
        self.textcursor.setPosition(0)
        self.log_browser.setTextCursor(self.textcursor)
        self.scan_running = False
        self.buttons_enable(True)

    def status_update(self):
        worker1 = Worker(self.status_plc)
        self.threadpool.start(worker1)
        worker2 = Worker(self.status_hmi)
        self.threadpool.start(worker2)

    def status_plc(self):
        while not self.exit_flag:
            result = attack.plc_status_check(self.get_plc_ip())
            if result == "No connection":
                self.plc_online = False
            else:
                self.plc_online = True
            self.buttons_enable(True)
            self.label_statusvalue.setText(result)
            sleep(polling_interval)
        print("PLC status polling stopped")

    def status_hmi(self):
        while not self.exit_flag:
            self.label_statusvalue_2.setText(self.ping(self.get_hmi_ip()))
            sleep(polling_interval*2)
        print("HMI status polling stopped")

    def moddisable(self, target):
        self.scan_running = True
        self.buttons_enable(False)
        self.show_log("* Executing PLC control disabling attack. Target [" + target + "]...\n")
        worker = Worker(attack.mb_stop, target)
        worker.signals.result.connect(self.print_output)
        worker.signals.finished.connect(lambda: self.thread_complete())
        self.threadpool.start(worker)

    def moddisrupt(self, target):
        self.scan_running = True
        self.buttons_enable(False)
        self.show_log("* Executing PLC operation disruption attack. Target [" + target + "]...\n")
        worker = Worker(attack.mb_disrupt, target)
        worker.signals.result.connect(self.print_output)
        worker.signals.finished.connect(lambda: self.thread_complete())
        self.threadpool.start(worker)

    def modrestore(self, target):
        self.scan_running = True
        self.buttons_enable(False)
        self.show_log("* Restoring PLC operation of target[" + target + "]...\n")
        worker = Worker(attack.mb_restore, target)
        worker.signals.result.connect(self.print_output)
        worker.signals.finished.connect(lambda: self.thread_complete())
        self.threadpool.start(worker)

    def tcpsyn(self, target):
        self.scan_running = True
        self.buttons_enable(False)
        self.show_log("* Performing TCP Syn scan of target[" + target + "]...\n")
        worker = Worker(attack.dos_syn, target)
        worker.signals.result.connect(self.print_output)
        worker.signals.finished.connect(lambda: self.thread_complete())
        self.threadpool.start(worker)

    def tcpxmas(self, target):
        self.scan_running = True
        self.buttons_enable(False)
        self.show_log("* Performing TCP Xmas scan of target[" + target + "]...\n")
        worker = Worker(attack.dos_xmas, target)
        worker.signals.result.connect(self.print_output)
        worker.signals.finished.connect(lambda: self.thread_complete())
        self.threadpool.start(worker)

    def eicar(self, target):
        self.scan_running = True
        self.buttons_enable(False)
        self.show_log("* Sending EICAR malware test packet to target[" + target + "]...\n")
        worker = Worker(attack.malware_eicar, target)
        worker.signals.result.connect(self.print_output)
        worker.signals.finished.connect(lambda: self.thread_complete())
        self.threadpool.start(worker)

    def passwd(self, target):
        self.scan_running = True
        self.buttons_enable(False)
        self.show_log("* Trying to retrieve password information from target[" + target + "]...\n")
        worker = Worker(attack.malware_passwd, target)
        worker.signals.result.connect(self.print_output)
        worker.signals.finished.connect(lambda: self.thread_complete())
        self.threadpool.start(worker)

    def cve_1(self, target):
        self.scan_running = True
        self.buttons_enable(False)
        self.show_log("* Exploiting CVE-2015-5374 Siemens SIPROTEC 4 and SIPROTEC Compact EN100 Ethernet Module < V4.25"
                      " - Denial of Service. Target [" + target + "]...\n")
        worker = Worker(attack.cve_2015_5374, target)
        worker.signals.result.connect(self.print_output)
        worker.signals.finished.connect(lambda: self.thread_complete())
        self.threadpool.start(worker)

    def cve_2(self, target):
        self.scan_running = True
        self.buttons_enable(False)
        self.show_log("* Exploiting CVE-2014-0750 GE Proficy CIMPLICITY HMI - Remote Code Execution. "
                      "Target [" + target + "]...\n")
        worker = Worker(attack.cve_2014_0750, target)
        worker.signals.result.connect(self.print_output)
        worker.signals.finished.connect(lambda: self.thread_complete())
        self.threadpool.start(worker)

    def cve_3(self, target):
        self.scan_running = True
        self.buttons_enable(False)
        self.show_log("* Exploiting CVE-2011-3486 Beckhoff TwinCAT PLC 2.11.0.2004 - Denial of Service. "
                      "Target [" + target + "]...\n")
        worker = Worker(attack.cve_2011_3486, target)
        worker.signals.result.connect(self.print_output)
        worker.signals.finished.connect(lambda: self.thread_complete())
        self.threadpool.start(worker)

    def cve_4(self, target):
        self.scan_running = True
        self.buttons_enable(False)
        self.show_log("* Exploiting CVE-2019-0708 BlueKeep RDP vunlnerability "
                      "Target [" + target + "]...\n")
        worker = Worker(bluekeep.cve_2019_0708, target)
        worker.signals.result.connect(self.print_output)
        worker.signals.finished.connect(lambda: self.thread_complete())
        self.threadpool.start(worker)

    def stop_thread(self):
        self.threadpool.globalInstance().waitForDone()
        self.threadpool.deleteLater()

    def __init__(self):
        super(Ui, self).__init__()
        uic.loadUi(ui_file, self)
        self.textcursor = QtGui.QTextCursor(self.log_browser.document())
        self.setWindowIcon(QtGui.QIcon(icon_file))
        self.buttons_plc = ["pushbutton_moddisable",
                            "pushbutton_moddisrupt",
                            "pushbutton_modrestore",
                            "pushbutton_tcpsyn",
                            "pushbutton_eicar",
                            "pushbutton_tcpxmas",
                            "pushbutton_passwd",
                            "pushbutton_cve_1",
                            "pushbutton_cve_2",
                            "pushbutton_cve_3"]
        self.buttons_hmi = ["pushbutton_tcpsyn_2",
                            "pushbutton_tcpxmas_2",
                            "pushbutton_eicar_2",
                            "pushbutton_passwd_2",
                            "pushbutton_cve_4"]
        self.exit_flag = False
        self.plc_online = False
        self.hmi_online = False
        self.scan_running = False
        self.buttons_enable(True)
        self.threadpool = QtCore.QThreadPool()
        self.threadpool.setMaxThreadCount(3)
        self.status_update()

        self.pushbutton_moddisable.clicked.connect(lambda: self.moddisable(self.get_plc_ip()))
        self.pushbutton_moddisrupt.clicked.connect(lambda: self.moddisrupt(self.get_plc_ip()))
        self.pushbutton_modrestore.clicked.connect(lambda: self.modrestore(self.get_plc_ip()))
        self.pushbutton_tcpsyn.clicked.connect(lambda: self.tcpsyn(self.get_plc_ip()))
        self.pushbutton_tcpxmas.clicked.connect(lambda: self.tcpxmas(self.get_plc_ip()))
        self.pushbutton_tcpsyn_2.clicked.connect(lambda: self.tcpsyn(self.get_hmi_ip()))
        self.pushbutton_tcpxmas_2.clicked.connect(lambda: self.tcpxmas(self.get_hmi_ip()))
        self.pushbutton_eicar.clicked.connect(lambda: self.eicar(self.get_plc_ip()))
        self.pushbutton_passwd.clicked.connect(lambda: self.passwd(self.get_plc_ip()))
        self.pushbutton_eicar_2.clicked.connect(lambda: self.eicar(self.get_hmi_ip()))
        self.pushbutton_passwd_2.clicked.connect(lambda: self.passwd(self.get_hmi_ip()))
        self.pushbutton_cve_1.clicked.connect(lambda: self.cve_1(self.get_plc_ip()))
        self.pushbutton_cve_2.clicked.connect(lambda: self.cve_2(self.get_plc_ip()))
        self.pushbutton_cve_3.clicked.connect(lambda: self.cve_3(self.get_plc_ip()))
        self.pushbutton_cve_4.clicked.connect(lambda: self.cve_4(self.get_hmi_ip()))

    def closeEvent(self, event):
        self.exit_flag = True
        self.stop_thread()


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    window = Ui()
    window.show()
    try:
        sys.exit(app.exec_())
    except:
        print("Exiting")
