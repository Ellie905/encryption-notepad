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


# Most of the following code has been borrowed from https://github.com/pyqt/examples/tree/_/src/07%20Qt%20Text%20Editor

import sys  # Used to Exit Application (sys.exit())
import base64  # Fernet Encryption Key requires base64 encoded byte
import cryptography  # Imported full library for InvalidToken Exception Handling below (inside decrypt_file())
from PyQt6.QtWidgets import *
from PyQt6.QtGui import QKeySequence, QAction
from Crypto.Hash import SHA256  # Used to hash files to get encryption key
from cryptography.fernet import Fernet


class MainWindow(QMainWindow):
    def closeEvent(self, e):
        if not text.document().isModified():
            return
        answer = QMessageBox.question(
            window, None,
            "You have unsaved changes. Save before closing?",
            QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel
        )
        if answer & QMessageBox.Save:
            save()
            if text.document().isModified():
                # This happens when the user closes the Save As... dialog.
                # We do not want to close the window in this case because it
                # would throw away unsaved changes.
                e.ignore()
        elif answer & QMessageBox.Cancel:
            e.ignore()


app = QApplication([])
app.setApplicationName("Text Editor")
text = QPlainTextEdit()
window = MainWindow()
window.setCentralWidget(text)

file_path = None
encryption_key: str = None


def hash_key_file(file):
    if isinstance(file, str):
        hash_object = SHA256.new(bytearray(file.encode()))
        return hash_object


def get_encryption_key():
    # open File Dialog, Pick File
    path = QFileDialog.getOpenFileName(window, "Pick Encryption Key")[0]

    global encryption_key

    try:
        file = open(path, errors="ignore").read()
    except FileNotFoundError:
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


# Pre-written function, modified to decrypt files upon opening
def open_file():
    global file_path
    path = QFileDialog.getOpenFileName(window, "Open")[0]

    # Decrypting
    with open(path, 'r') as file:
        plaintext = decrypt_file(file.read())

    text.setPlainText(plaintext)
    file_path = path


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


# Pre-written function, unmodified
def save_as():
    global file_path
    path = QFileDialog.getSaveFileName(window, "Save As")[0]
    if path:
        file_path = path
        save()


# --- Python GUI Options ---

menu = window.menuBar().addMenu("&File")

# Adds menu option, "Open" to open files
open_action = QAction("&Open")
open_action.triggered.connect(open_file)
open_action.setShortcut(QKeySequence.StandardKey.Open)
menu.addAction(open_action)

save_action = QAction("&Save")
save_action.triggered.connect(save)
save_action.setShortcut(QKeySequence.StandardKey.Save)
menu.addAction(save_action)

save_as_action = QAction("Save &As...")
save_as_action.triggered.connect(save_as)
menu.addAction(save_as_action)

close = QAction("&Close")
close.triggered.connect(window.close)
menu.addAction(close)

# New menu option, allows user to select different file to hash for encryption key, without restarting app
get_new_key_action = QAction("&Pick New Encryption Key")
get_new_key_action.triggered.connect(get_encryption_key)
menu.addAction(get_new_key_action)


# --- Execution ---


# Before Form shows, select file to be hashed for encryption key
get_encryption_key()

window.show()
app.exec()
