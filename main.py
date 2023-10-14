from math import gcd

import sys

from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QMessageBox, QSpinBox


######## LOGIC ######################################################################

def strtonumber(sequence):  # Convert each character [A-Z] into an numeric index [0-25]

    numseq = []

    for c in sequence:
        numseq.append(ord(c) - 65)

    return numseq


def numbertostr(numseq):  # Convert each index [0-25] into its assigned character [A-Z]

    sequence = ""

    for n in numseq:
        sequence += (chr(n + 65))

    return sequence


def encrypt(OT, a, b):  # Encrypting function: CT = (OT(letter)*a + b) mod 26

    numseq = strtonumber(OT.upper())  # Obtains the numbers sequence from the given string
    cipherseq = []

    for n in numseq:
        cipherseq.append((n * a + b) % 26)

    return numbertostr(cipherseq)


def modularinverse(a):  # Finds the modular inverse of a

    # We need to find x in: x*a mod 26 = 1

    for x in range(1, 25):
        if (x * a) % 26 == 1:
            return x

    return None


def decrypt(CT, a, b):  # Decrypting function: OT = ((CT - b)*(a^-1)) mod 26

    numseq = strtonumber(CT)  # Obtains the numbers sequence from the given string
    sequence = []
    inverse = modularinverse(a)

    for n in numseq:
        sequence.append(((n - b) * inverse) % 26)
    return numbertostr(sequence)


def check_a(a):  # Check the value of "a"

    return (a != 0) and (gcd(a, 26) == 1)




######## GRAPHIC USER INTERFACE #####################################################

class Window(QWidget):

    def __init__(self):
        super().__init__()
        self.initializeUI()

    def initializeUI(self):
        self.setGeometry(100, 100, 480, 370)  # PosX, PosY, Width, Height
        self.setWindowTitle("Affine Cipher")
        self.generate_layout()
        self.show()

    def generate_layout(self):

        # Keys ############################################

        keys_title_height = 20
        keys_title = QLabel(self)
        keys_title.setText("Keys:")
        keys_title.setFont(QFont('Arial', 15))
        keys_title.move(20, keys_title_height)

        # Value a
        a_hint = QLabel(self)
        a_hint.setText("Value for \"a\":")
        a_hint.setFont(QFont('Arial', 10))
        a_hint.move(20, keys_title_height + 30)

        self.a_input = QSpinBox(self)
        self.a_input.setRange(1, 25)
        self.a_input.resize(40, 24)  # Width x Height
        self.a_input.move(100, keys_title_height + 25)

        # Value b
        b_hint = QLabel(self)
        b_hint.setText("Value for \"b\":")
        b_hint.setFont(QFont('Arial', 10))
        b_hint.move(150, keys_title_height + 30)

        self.b_input = QSpinBox(self)
        self.b_input.setRange(-1000, 1000)
        self.b_input.resize(60, 24)  # Width x Height
        self.b_input.move(230, keys_title_height + 25)

        # Encrypt ##########################################

        cipher_title_height = 100
        cipher_title = QLabel(self)
        cipher_title.setText("Encryption:")
        cipher_title.setFont(QFont('Arial', 15))
        cipher_title.move(20, cipher_title_height)

        self.opentextIsValid = False
        self.text_input = QLineEdit(self)
        self.text_input.setPlaceholderText("Insert open text")
        self.text_input.resize(200, 24)  # Width x Height
        self.text_input.move(20, cipher_title_height + 30)
        self.text_input.textChanged.connect(self.validateTextInput)

        self.ot_valid_info = QLabel(self)
        self.ot_valid_info.setFont(QFont('Arial', 10, 0, True))
        self.ot_valid_info.resize(250, 20)
        self.ot_valid_info.move(230, cipher_title_height + 32)

        self.text_output = QLineEdit(self)
        self.text_output.setReadOnly(True)
        self.text_output.setPlaceholderText("Encrypted text will appear here")
        self.text_output.resize(200, 24)  # Width x Height
        self.text_output.move(20, cipher_title_height + 60)

        encrypt_button = QPushButton(self)
        encrypt_button.setText("Encrypt")
        encrypt_button.resize(60, 24)
        encrypt_button.move(230, cipher_title_height + 60)
        encrypt_button.clicked.connect(self.startEncryption)

        # Decrypt ##############################################

        decipher_title_height = 220
        decipher_title = QLabel(self)
        decipher_title.setText("Decryption:")
        decipher_title.setFont(QFont('Arial', 15))
        decipher_title.move(20, decipher_title_height)

        self.ciphertextIsValid = False
        self.ciphered_input = QLineEdit(self)
        self.ciphered_input.setPlaceholderText("Insert cipher text")
        self.ciphered_input.resize(200, 24)  # Width x Height
        self.ciphered_input.move(20, decipher_title_height + 30)
        self.ciphered_input.textChanged.connect(self.validateCipheredInput)

        self.ct_valid_info = QLabel(self)
        self.ct_valid_info.setFont(QFont('Arial', 10, 0, True))
        self.ct_valid_info.resize(250, 20)
        self.ct_valid_info.move(230, decipher_title_height + 32)

        self.cipher_output = QLineEdit(self)
        self.cipher_output.setReadOnly(True)
        self.cipher_output.setPlaceholderText("Decrypted text will appear here")
        self.cipher_output.resize(200, 24)  # Width x Height
        self.cipher_output.move(20, decipher_title_height + 60)

        decrypt_button = QPushButton(self)
        decrypt_button.setText("Decrypt")
        decrypt_button.resize(60, 24)
        decrypt_button.move(230, decipher_title_height + 60)
        decrypt_button.clicked.connect(self.startDecryption)


    def validateTextInput(self):

        text = self.text_input.text()

        if text == "":
            self.opentextIsValid = False
            self.ot_valid_info.setText("Empty string")
        elif not text.isalpha():
            self.opentextIsValid = False
            self.ot_valid_info.setText("Only alphabetical characters are allowed")
        else:
            self.opentextIsValid = True
            self.ot_valid_info.setText("✔️")

    def validateCipheredInput(self):
        text = self.ciphered_input.text()

        if text == "":
            self.ciphertextIsValid = False
            self.ct_valid_info.setText("Empty string")
        elif not text.isalpha():
            self.ciphertextIsValid = False
            self.ct_valid_info.setText("Only alphabetical characters are allowed")
        else:
            self.ciphertextIsValid = True
            self.ct_valid_info.setText("✔️")

    def startEncryption(self):

        a = int(self.a_input.text())

        if not check_a(a):
            QMessageBox.warning(self, "Invalid Key Error",
            "The greatest common divider between \"a\" and 26 must be 1.\nTry another value for \"a\".",
            QMessageBox.StandardButton.Close, QMessageBox.StandardButton.Close)
        elif not self.opentextIsValid:
            if self.text_input.text() == "":
                self.text_output.setText("")
                QMessageBox.warning(self, "Invalid Text Input",
                "Text input is empty.",
                QMessageBox.StandardButton.Close, QMessageBox.StandardButton.Close)
            else:
                QMessageBox.warning(self, "Invalid Text Input",
                "Only alphabetical characters are allowed.",
                QMessageBox.StandardButton.Close, QMessageBox.StandardButton.Close)
        else:
            self.text_output.setText(encrypt(self.text_input.text(), a, int(self.b_input.text())))

    def startDecryption(self):
        a = int(self.a_input.text())

        if not check_a(a):
            QMessageBox.warning(self, "Invalid Key Error",
            "The greatest common divider between \"a\" and 26 must be 1.\nTry another value for \"a\".",
            QMessageBox.StandardButton.Close, QMessageBox.StandardButton.Close)
        elif not self.ciphertextIsValid:
            if self.ciphered_input.text() == "":
                self.cipher_output.setText("")
                QMessageBox.warning(self, "Invalid Ciphertext Input",
                "Ciphertext input is empty.",
                QMessageBox.StandardButton.Close, QMessageBox.StandardButton.Close)
            else:
                QMessageBox.warning(self, "Invalid Ciphertext Input",
                "Only alphabetical characters are allowed.",
                QMessageBox.StandardButton.Close, QMessageBox.StandardButton.Close)
        else:
            self.cipher_output.setText(decrypt(self.ciphered_input.text(), a, int(self.b_input.text())))



if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = Window()
    sys.exit(app.exec())

