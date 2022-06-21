# Project: Encrypted Notepad Application written in Python with PyQt6
# Author: Ellie Day
# Date: June 19th 2022

# Purpose: A recreation of an old tool I made in VB.Net and Visual Studio. An application similar to Windows' Notepad
# application that secures the integrity of the data by encrypting/decrypting automatically - using a separate file
# as the 'key'

# File chosen as encryption key should be something personal (so, not a shortcut to Google Chrome's executable for
# example), and something that remains relatively constant. If the encryption key file is ever changed, the resulting
# future hash values will be altered from the original, resulting in a different encryption key. If the file is
# changed, encrypted documents will be irretrievable through normal means.

# Docs: https://www.riverbankcomputing.com/static/Docs/PyQt6/index.html


# ---- TO-DO (in the future) ----
# Exit Code 250 - Replace with QMessageBox informing user they have the incorrect encryption key, then run close_file()
# Removed Fixed x, y coords of window geometry in MainWindow.__init__() (Percentage instead of Fixed)


# Most of the following code initially was borrowed from
# https://github.com/pyqt/examples/tree/_/src/07%20Qt%20Text%20Editor

import sys  # Used to Exit Application (sys.exit())
import base64  # Fernet Encryption Key requires base64 encoded byte
import cryptography  # Imported full library for InvalidToken Exception Handling below (inside decrypt_file())
import ntpath  # NTPath added to give window dynamic features
from PyQt6.QtWidgets import *
from PyQt6.QtGui import QKeySequence, QAction
from Crypto.Hash import SHA256  # Used to hash files to get encryption key
from cryptography.fernet import Fernet


class MainWindow(QMainWindow):
    # event handler (signal) listening for textbox changes
    def __init__(self):
        super().__init__()

        text.textChanged.connect(self.file_has_changed)

        # x, y, width, height
        self.setGeometry(650, 300, 650, 400)

    # original function causes crashes, modified to prevent instability
    def closeEvent(self, e):
        if not text.document().isModified():
            return

        dlg = Dialog(self)
        answer = dlg.exec()

        if answer == 0:  # Cancel
            e.ignore()
        elif answer == 1:  # Save
            save()
            if text.document().isModified():
                # This happens when the user closes the Save As... dialog.
                # We do not want to close the window in this case because it
                # would throw away unsaved changes.
                e.ignore()

    # once signal is processed, window title is changed to reflect unsaved changes made to document
    def file_has_changed(self):
        text.document().setModified(True)
        if window.windowTitle().__contains__('*'):
            return
        window.setWindowTitle(window.windowTitle() + ' *')


class Dialog(QDialog):
    def __init__(self, parent=MainWindow):
        super().__init__()

        self.setWindowTitle("Warning!")

        QDiscardBtn: QAbstractButton = QPushButton("&Discard", self)
        QBtn = QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel

        self.buttonBox = QDialogButtonBox(QBtn)
        self.buttonBox.accepted.connect(self.accept)
        self.buttonBox.rejected.connect(self.reject)

        self.buttonBox.addButton(QDiscardBtn, QDialogButtonBox.ButtonRole(2))
        QDiscardBtn.clicked.connect(self.discard)

        self.layout = QVBoxLayout()
        message = QLabel("You have unsaved changes. Save before closing?")
        self.layout.addWidget(message)
        self.layout.addWidget(self.buttonBox)
        self.setLayout(self.layout)

    def discard(self):
        app.exit(0)


# Rather than close application, this Dialog closes the file so user can create a new document
class CloseDialog(Dialog):
    def __init__(self, parent=MainWindow):
        super().__init__()

    def discard(self):
        text.setPlainText('')
        text.document().setModified(False)
        window.setWindowTitle('Untitled Document')
        self.close()


app = QApplication([])
app.setApplicationName("Text Editor")
text = QPlainTextEdit()
window = MainWindow()
window.setCentralWidget(text)

file_path: str = ''
encryption_key: str = ''


def get_file_name(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)


def hash_key_file(file):
    if isinstance(file, str):
        hash_object = SHA256.new(bytearray(file.encode()))
        return hash_object


def get_encryption_key():
    global encryption_key

    # open File Dialog, Pick File
    path = QFileDialog.getOpenFileName(window, "Pick Encryption Key")[0]

    try:
        file = open(path, errors="ignore").read()
    except FileNotFoundError:
        # user selected new encryption key, opened QFileDialog, but closed it without picking new file
        # old file is reused
        if encryption_key is not None:
            return

        # exit application if user doesn't select file to hash for encryption key - Exit Code #30
        sys.exit(30)
    else:
        # hashes the file and returns the value (first 256 bits)
        encryption_key = hash_key_file(file).hexdigest()[:32]


def decrypt_file(file):
    try:
        # file is passed from open_file(), file is the raw text from the text file in a str object
        payload = str.encode(file)

        # decrypt data
        key = base64.b64encode(str.encode(encryption_key))
        fer = Fernet(key)
        token = fer.decrypt(payload)

        # returns str object of decrypted data, no padding
        plaintext = bytes.decode(token)
        return plaintext
    except cryptography.fernet.InvalidToken:
        # Exit application if user selected incorrect file to hash for encryption key, thus user received incorrect key
        # Exit Code #250
        sys.exit(250)


def close_file():
    if not text.document().isModified():
        text.clear()
        text.document().setModified(False)
        window.setWindowTitle('Untitled Document')
        return

    dlg = CloseDialog()
    answer = dlg.exec()

    if answer == 0:  # Cancel
        return
    elif answer == 1:  # Save
        save()


# Pre-written function, modified to decrypt files upon opening
def open_file():
    if text.document().isModified():
        close_file()

    global file_path
    path = QFileDialog.getOpenFileName(window, "Open")[0]

    # Decrypting
    try:
        with open(path, 'r') as file:
            plaintext = decrypt_file(file.read())
    except FileNotFoundError:
        return

    text.setPlainText(plaintext)
    file_path = path

    window.setWindowTitle(get_file_name(path))


# Pre-written function, modified to encrypt files upon saving
def save():
    if file_path is None:
        save_as()
    else:
        # Encrypting
        with open(file_path, "w") as f:
            key = base64.b64encode(str.encode(encryption_key))
            plaintext = text.toPlainText()
            payload = str.encode(plaintext, 'utf-8')

            fer = Fernet(key)
            token = fer.encrypt(payload)

            f.write(bytes.decode(token))

        text.document().setModified(False)

        window.setWindowTitle(str(window.windowTitle()).rstrip(' *'))

        if window.windowTitle() == 'Untitled Document':
            window.setWindowTitle(get_file_name(file_path))


# Pre-written function, unmodified
def save_as():
    global file_path
    path = QFileDialog.getSaveFileName(window, "Save As")[0]
    if path:
        file_path = path
        save()


# --- Python GUI Options ---

fileMenu = window.menuBar().addMenu("&File")
toolsMenu = window.menuBar().addMenu("&Tools")

# - File Menu -

new_action = QAction("&New")
new_action.triggered.connect(close_file)
new_action.setShortcut(QKeySequence.StandardKey.New)
fileMenu.addAction(new_action)

# Adds menu option, "Open" to open files
open_action = QAction("&Open")
open_action.triggered.connect(open_file)
open_action.setShortcut(QKeySequence.StandardKey.Open)
fileMenu.addAction(open_action)

save_action = QAction("&Save")
save_action.triggered.connect(save)
save_action.setShortcut(QKeySequence.StandardKey.Save)
fileMenu.addAction(save_action)

save_as_action = QAction("Save &As...")
save_as_action.triggered.connect(save_as)
fileMenu.addAction(save_as_action)

close = QAction("&Exit")
close.triggered.connect(window.close)
fileMenu.addAction(close)

# - Tools Menu

new_key_action = QAction("Select New Encryption &Key")
new_key_action.triggered.connect(get_encryption_key)
toolsMenu.addAction(new_key_action)

# --- Execution ---


# Before Form shows, select file to be hashed for encryption key
get_encryption_key()

window.setWindowTitle("Untitled Document")
window.show()

app.exec()
