import sys
import struct
import shutil
import io
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget,
    QFileDialog, QLabel, QMessageBox, QComboBox, QLineEdit
)

def gather_file_info_win(binary):
    """
    Gather information from a Windows PE file.

    Args:
        binary (str): Path to the binary file.

    Returns:
        dict: A dictionary containing various fields from the PE file.
    """
    flItms = {}
    binary = open(binary, 'rb')
    binary.seek(int('3C', 16))
    flItms['buffer'] = 0
    flItms['JMPtoCodeAddress'] = 0
    flItms['dis_frm_pehdrs_sectble'] = 248
    flItms['pe_header_location'] = struct.unpack('<i', binary.read(4))[0]
    flItms['COFF_Start'] = flItms['pe_header_location'] + 4
    binary.seek(flItms['COFF_Start'])
    flItms['MachineType'] = struct.unpack('<H', binary.read(2))[0]
    binary.seek(flItms['COFF_Start'] + 2, 0)
    flItms['NumberOfSections'] = struct.unpack('<H', binary.read(2))[0]
    flItms['TimeDateStamp'] = struct.unpack('<I', binary.read(4))[0]
    binary.seek(flItms['COFF_Start'] + 16, 0)
    flItms['SizeOfOptionalHeader'] = struct.unpack('<H', binary.read(2))[0]
    flItms['Characteristics'] = struct.unpack('<H', binary.read(2))[0]
    flItms['OptionalHeader_start'] = flItms['COFF_Start'] + 20

    binary.seek(flItms['OptionalHeader_start'])
    flItms['Magic'] = struct.unpack('<H', binary.read(2))[0]
    flItms['MajorLinkerVersion'] = struct.unpack("!B", binary.read(1))[0]
    flItms['MinorLinkerVersion'] = struct.unpack("!B", binary.read(1))[0]
    flItms['SizeOfCode'] = struct.unpack("<I", binary.read(4))[0]
    flItms['SizeOfInitializedData'] = struct.unpack("<I", binary.read(4))[0]
    flItms['SizeOfUninitializedData'] = struct.unpack("<I", binary.read(4))[0]
    flItms['AddressOfEntryPoint'] = struct.unpack('<I', binary.read(4))[0]
    flItms['PatchLocation'] = flItms['AddressOfEntryPoint']
    flItms['BaseOfCode'] = struct.unpack('<I', binary.read(4))[0]
    if flItms['Magic'] != 0x20B:
        flItms['BaseOfData'] = struct.unpack('<I', binary.read(4))[0]
    if flItms['Magic'] == 0x20B:
        flItms['ImageBase'] = struct.unpack('<Q', binary.read(8))[0]
    else:
        flItms['ImageBase'] = struct.unpack('<I', binary.read(4))[0]
    flItms['SectionAlignment'] = struct.unpack('<I', binary.read(4))[0]
    flItms['FileAlignment'] = struct.unpack('<I', binary.read(4))[0]
    flItms['MajorOperatingSystemVersion'] = struct.unpack('<H', binary.read(2))[0]
    flItms['MinorOperatingSystemVersion'] = struct.unpack('<H', binary.read(2))[0]
    flItms['MajorImageVersion'] = struct.unpack('<H', binary.read(2))[0]
    flItms['MinorImageVersion'] = struct.unpack('<H', binary.read(2))[0]
    flItms['MajorSubsystemVersion'] = struct.unpack('<H', binary.read(2))[0]
    flItms['MinorSubsystemVersion'] = struct.unpack('<H', binary.read(2))[0]
    flItms['Win32VersionValue'] = struct.unpack('<I', binary.read(4))[0]
    flItms['SizeOfImageLoc'] = binary.tell()
    flItms['SizeOfImage'] = struct.unpack('<I', binary.read(4))[0]
    flItms['SizeOfHeaders'] = struct.unpack('<I', binary.read(4))[0]
    flItms['CheckSum'] = struct.unpack('<I', binary.read(4))[0]
    flItms['Subsystem'] = struct.unpack('<H', binary.read(2))[0]
    flItms['DllCharacteristics'] = struct.unpack('<H', binary.read(2))[0]
    if flItms['Magic'] == 0x20B:
        flItms['SizeOfStackReserve'] = struct.unpack('<Q', binary.read(8))[0]
        flItms['SizeOfStackCommit'] = struct.unpack('<Q', binary.read(8))[0]
        flItms['SizeOfHeapReserve'] = struct.unpack('<Q', binary.read(8))[0]
        flItms['SizeOfHeapCommit'] = struct.unpack('<Q', binary.read(8))[0]
    else:
        flItms['SizeOfStackReserve'] = struct.unpack('<I', binary.read(4))[0]
        flItms['SizeOfStackCommit'] = struct.unpack('<I', binary.read(4))[0]
        flItms['SizeOfHeapReserve'] = struct.unpack('<I', binary.read(4))[0]
        flItms['SizeOfHeapCommit'] = struct.unpack('<I', binary.read(4))[0]
    flItms['LoaderFlags'] = struct.unpack('<I', binary.read(4))[0]  # zero
    flItms['NumberofRvaAndSizes'] = struct.unpack('<I', binary.read(4))[0]
    flItms['ExportTableRVA'] = struct.unpack('<I', binary.read(4))[0]
    flItms['ExportTableSize'] = struct.unpack('<I', binary.read(4))[0]
    flItms['ImportTableLOCInPEOptHdrs'] = binary.tell()
    flItms['ImportTableRVA'] = struct.unpack('<I', binary.read(4))[0]
    flItms['ImportTableSize'] = struct.unpack('<I', binary.read(4))[0]
    flItms['ResourceTable'] = struct.unpack('<Q', binary.read(8))[0]
    flItms['ExceptionTable'] = struct.unpack('<Q', binary.read(8))[0]
    flItms['CertTableLOC'] = binary.tell()
    flItms['CertLOC'] = struct.unpack("<I", binary.read(4))[0]
    flItms['CertSize'] = struct.unpack("<I", binary.read(4))[0]
    binary.close()
    return flItms


def copyCert(exe):
    flItms = gather_file_info_win(exe)
    if flItms['CertLOC'] == 0 or flItms['CertSize'] == 0:
        return None
    with open(exe, 'rb') as f:
        f.seek(flItms['CertLOC'], 0)
        cert = f.read(flItms['CertSize'])
    return cert


def writeCert(cert, exe, output):
    flItms = gather_file_info_win(exe)
    if not output:
        output = str(exe) + "_signed"
    shutil.copy2(exe, output)
    with open(exe, 'rb') as g:
        with open(output, 'wb') as f:
            f.write(g.read())
            f.seek(0)
            f.seek(flItms['CertTableLOC'], 0)
            f.write(struct.pack("<I", len(open(exe, 'rb').read())))
            f.write(struct.pack("<I", len(cert)))
            f.seek(0, io.SEEK_END)
            f.write(cert)


def outputCert(exe, output):
    cert = copyCert(exe)
    if not output:
        output = str(exe) + "_sig"
    if cert is not None:
        with open(output, 'wb') as f:
            f.write(cert)


def check_sig(exe):
    flItms = gather_file_info_win(exe)
    return not (flItms['CertLOC'] == 0 or flItms['CertSize'] == 0)


def truncate(exe, output):
    flItms = gather_file_info_win(exe)
    if flItms['CertLOC'] == 0 or flItms['CertSize'] == 0:
        return None
    if not output:
        output = str(exe) + "_nosig"
    shutil.copy2(exe, output)
    with open(output, "r+b") as binary:
        binary.seek(-flItms['CertSize'], io.SEEK_END)
        binary.truncate()
        binary.seek(flItms['CertTableLOC'], 0)
        binary.write(b"\x00\x00\x00\x00\x00\x00\x00\x00")
    return output


def signfile(exe, sigfile, output):
    flItms = gather_file_info_win(exe)
    cert = open(sigfile, 'rb').read()
    if not output:
        output = str(exe) + "_signed"
    shutil.copy2(exe, output)
    with open(exe, 'rb') as g:
        with open(output, 'wb') as f:
            f.write(g.read())
            f.seek(0)
            f.seek(flItms['CertTableLOC'], 0)
            f.write(struct.pack("<I", len(open(exe, 'rb').read())))
            f.write(struct.pack("<I", len(cert)))
            f.seek(0, io.SEEK_END)
            f.write(cert)


class FileSignatureApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('PyTheRipper')
        self.setGeometry(100, 100, 600, 300)

        layout = QVBoxLayout()

        self.fileLabel = QLabel('Select Input File:')
        layout.addWidget(self.fileLabel)

        self.fileEdit = QLineEdit()
        layout.addWidget(self.fileEdit)

        self.fileButton = QPushButton('Browse')
        self.fileButton.clicked.connect(self.openFileNameDialog)
        layout.addWidget(self.fileButton)

        self.actionComboBox = QComboBox()
        self.actionComboBox.addItem('Select Action')
        self.actionComboBox.addItem('Rip Signature')
        self.actionComboBox.addItem('Add Signature')
        self.actionComboBox.addItem('Check Signature')
        self.actionComboBox.addItem('Truncate Signature')
        layout.addWidget(self.actionComboBox)

        self.outputLabel = QLabel('Output File (optional):')
        layout.addWidget(self.outputLabel)

        self.outputEdit = QLineEdit()
        layout.addWidget(self.outputEdit)

        self.signatureLabel = QLabel('Signature File (for Add Signature action):')
        layout.addWidget(self.signatureLabel)

        self.signatureEdit = QLineEdit()
        layout.addWidget(self.signatureEdit)

        self.executeButton = QPushButton('Execute')
        self.executeButton.clicked.connect(self.executeAction)
        layout.addWidget(self.executeButton)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def openFileNameDialog(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, 'Select File', '', 'All Files (*);;PE Files (*.exe)', options=options)
        if file_name:
            self.fileEdit.setText(file_name)

    def executeAction(self):
        action = self.actionComboBox.currentText()
        input_file = self.fileEdit.text()
        output_file = self.outputEdit.text()
        sig_file = self.signatureEdit.text()

        if action == 'Select Action':
            QMessageBox.warning(self, 'Warning', 'Please select an action.')
            return

        if not input_file:
            QMessageBox.warning(self, 'Warning', 'Please select an input file.')
            return

        if action == 'Rip Signature':
            outputCert(input_file, output_file)
            QMessageBox.information(self, 'Success', f'Signature ripped to {output_file}')
        elif action == 'Add Signature':
            if not sig_file:
                QMessageBox.warning(self, 'Warning', 'Please provide a signature file.')
                return
            signfile(input_file, sig_file, output_file)
            QMessageBox.information(self, 'Success', f'Signature added to {output_file}')
        elif action == 'Check Signature':
            if check_sig(input_file):
                QMessageBox.information(self, 'Result', 'File is signed!')
            else:
                QMessageBox.information(self, 'Result', 'File is not signed.')
        elif action == 'Truncate Signature':
            result_file = truncate(input_file, output_file)
            if result_file:
                QMessageBox.information(self, 'Success', f'Signature removed and file saved as {result_file}')
            else:
                QMessageBox.warning(self, 'Warning', 'File is not signed.')

if __name__ == "__main__":
    app = QApplication(sys.argv)
    ex = FileSignatureApp()
    ex.show()
    sys.exit(app.exec_())
