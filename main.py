import sys
import traceback
from PyQt5 import QtWidgets, uic, QtCore
from lib import attack
from time import sleep

# CONSTANTS
polling_interval = 3
ui_file = "lib/interface.ui"

# For debug purposes since pyQT does not display exception details [
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

    def print_output(self, message):
        self.show_log(message)

    def thread_complete(self, button_name):
        self.show_log("[DONE]\n")
        eval("self." + button_name + ".setEnabled(True)")

    def status_update(self):
        worker1 = Worker(self.status_plc)
        self.threadpool.start(worker1)
        worker2 = Worker(self.status_hmi)
        self.threadpool.start(worker2)

    def status_plc(self):
        while True:
            self.label_statusvalue.setText(attack.plc_status_check(self.get_plc_ip()))
            sleep(polling_interval)

    def status_hmi(self):
        while True:
            self.label_statusvalue_2.setText(self.get_hmi_ip())
            sleep(polling_interval)

    def moddisable(self, target):
        button_name = "pushbutton_moddisable"
        self.pushbutton_moddisable.setEnabled(False)
        self.show_log("Executing PLC control disabling attack. Target [" + target + "]...")
        worker = Worker(attack.mb_stop, self.get_plc_ip())
        worker.signals.result.connect(self.print_output)
        worker.signals.finished.connect(lambda: self.thread_complete(button_name))
        self.threadpool.start(worker)

    def moddisrupt(self, target):
        button_name = "pushbutton_moddisrupt"
        self.pushbutton_moddisrupt.setEnabled(False)
        self.show_log("Executing PLC operation disruption attack. Target [" + target + "]...")
        worker = Worker(attack.mb_disrupt, self.get_plc_ip())
        worker.signals.result.connect(self.print_output)
        worker.signals.finished.connect(lambda: self.thread_complete(button_name))
        self.threadpool.start(worker)

    def modrestore(self, target):
        button_name = "pushbutton_modrestore"
        self.pushbutton_modrestore.setEnabled(False)
        self.show_log("Restoring PLC operation of target[" + target + "]...")
        worker = Worker(attack.mb_restore, self.get_plc_ip())
        worker.signals.result.connect(self.print_output)
        worker.signals.finished.connect(lambda: self.thread_complete(button_name))
        self.threadpool.start(worker)

    def tcpsyn(self, target):
        button_name = "pushbutton_tcpsyn"
        self.pushbutton_tcpsyn.setEnabled(False)
        self.show_log("Performing TCP Syn scan of target[" + target + "]")
        worker = Worker(attack.dos_syn, self.get_plc_ip())
        worker.signals.result.connect(self.print_output)
        worker.signals.finished.connect(lambda: self.thread_complete(button_name))
        self.threadpool.start(worker)

    def tcpxmas(self, target):
        button_name = "pushbutton_tcpxmas"
        self.pushbutton_tcpxmas.setEnabled(False)
        self.show_log("Performing TCP Xmas scan of target[" + target + "]")
        worker = Worker(attack.dos_xmas, self.get_plc_ip())
        worker.signals.result.connect(self.print_output)
        worker.signals.finished.connect(lambda: self.thread_complete(button_name))
        self.threadpool.start(worker)

    def eicar(self, target):
        button_name = "pushbutton_eicar"
        self.pushbutton_eicar.setEnabled(False)
        self.show_log("Sending EICAR malware test packet to target[" + target + "]...")
        self.show_log(attack.malware_eicar(self.get_plc_ip()))
        worker = Worker(attack.malware_eicar, self.get_plc_ip())
        worker.signals.result.connect(self.print_output)
        worker.signals.finished.connect(lambda: self.thread_complete(button_name))
        self.threadpool.start(worker)

    def passwd(self, target):
        button_name = "pushbutton_passwd"
        self.pushbutton_passwd.setEnabled(False)
        self.show_log("Trying to retrieve password information from target[" + target + "]...")
        worker = Worker(attack.malware_passwd, self.get_plc_ip())
        worker.signals.result.connect(self.print_output)
        worker.signals.finished.connect(lambda: self.thread_complete(button_name))
        self.threadpool.start(worker)

    def cve_1(self, target):
        button_name = "pushbutton_cve_1"
        self.pushbutton_cve_1.setEnabled(False)
        self.show_log("Exploiting CVE-2015-5374 Siemens SIPROTEC 4 and SIPROTEC Compact EN100 Ethernet Module < V4.25 -"
                      " Denial of Service. Target [" + target + "]")
        worker = Worker(attack.cve_2015_5374, self.get_plc_ip())
        worker.signals.result.connect(self.print_output)
        worker.signals.finished.connect(lambda: self.thread_complete(button_name))
        self.threadpool.start(worker)

    def cve_2(self, target):
        button_name = "pushbutton_cve_2"
        self.pushbutton_cve_2.setEnabled(False)
        self.show_log("Exploiting CVE-2014-0750 GE Proficy CIMPLICITY HMI - Remote Code Execution. "
                      "Target [" + target + "]")
        worker = Worker(attack.cve_2014_0750, self.get_plc_ip())
        worker.signals.result.connect(self.print_output)
        worker.signals.finished.connect(lambda: self.thread_complete(button_name))
        self.threadpool.start(worker)

    def cve_3(self, target):
        button_name = "pushbutton_cve_3"
        self.pushbutton_cve_3.setEnabled(False)
        self.show_log("Exploiting CVE-2011-3486 Beckhoff TwinCAT PLC 2.11.0.2004 - Denial of Service. "
                      "Target [" + target + "]")
        worker = Worker(attack.cve_2011_3486, self.get_plc_ip())
        worker.signals.result.connect(self.print_output)
        worker.signals.finished.connect(lambda: self.thread_complete(button_name))
        self.threadpool.start(worker)

    def cve_4(self, target):
        self.show_log("Check [" + target + "]")

    def stop_thread(self):
        self.threadpool.globalInstance().waitForDone()
        self.threadpool.deleteLater()

    def __init__(self):
        super(Ui, self).__init__()
        uic.loadUi(ui_file, self)
        self.threadpool = QtCore.QThreadPool()
        self.status_update()

        self.pushbutton_moddisable.clicked.connect(lambda: self.moddisable(self.get_plc_ip()))
        self.pushbutton_moddisrupt.clicked.connect(lambda: self.moddisrupt(self.get_plc_ip()))
        self.pushbutton_modrestore.clicked.connect(lambda: self.modrestore(self.get_plc_ip()))
        self.pushbutton_tcpsyn.clicked.connect(lambda: self.tcpsyn(self.get_plc_ip()))
        self.pushbutton_tcpxmas.clicked.connect(lambda: self.tcpxmas(self.get_plc_ip()))
        self.pushbutton_eicar.clicked.connect(lambda: self.eicar(self.get_plc_ip()))
        self.pushbutton_passwd.clicked.connect(lambda: self.passwd(self.get_plc_ip()))
        self.pushbutton_cve_1.clicked.connect(lambda: self.cve_1(self.get_plc_ip()))
        self.pushbutton_cve_2.clicked.connect(lambda: self.cve_2(self.get_plc_ip()))
        self.pushbutton_cve_3.clicked.connect(lambda: self.cve_3(self.get_plc_ip()))
        self.pushbutton_cve_4.clicked.connect(lambda: self.cve_4(self.get_hmi_ip()))

    def closeEvent(self, event):
        self.stop_thread()
        sys.exit(0)


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    window = Ui()
    window.show()
    try:
        sys.exit(app.exec_())
    except:
        print("Exiting")
