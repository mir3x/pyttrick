import contextlib
import json
import logging
import os
import sys
import urllib.request
import xml.etree.ElementTree as ET
from urllib.parse import quote_plus, urlencode

import oauth2 as oauth
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (QApplication, QDialog, QGridLayout, QLabel,
                             QLineEdit, QMainWindow, QMessageBox, QPushButton,
                             QTabWidget, QTextEdit, QVBoxLayout, QWidget)

logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)

REQUEST_TOKEN = 'https://chpp.hattrick.org/oauth/request_token.ashx'
AUTHORIZE = 'https://chpp.hattrick.org/oauth/authorize.aspx'
AUTHENTHICATE = 'https://chpp.hattrick.org/oauth/authenticate.aspx'
ACCESS_TOKEN = 'https://chpp.hattrick.org/oauth/access_token.ashx'
CHECK_TOKEN = 'https://chpp.hattrick.org/oauth/check_token.ashx'
INVALIDATE_TOKEN = 'https://chpp.hattrick.org/oauth/invalidate_token.ashx'
HT_RESOURCES = 'https://chpp.hattrick.org/chppxml.ashx'

CONSUMER_KEY = 'MSFQ72LlchPtooUdf3Iyfsg4p5MvXs07Q5S271Dsrf3x'
CONSUMER_SECRET = 'tqwx6d9416N6K3JdonjdQszzXdweCcmc3sowjgAeGge3dtYtp3NeLtbd23E3IsewQfNbjeVfQdsa3fIvOtDfwr'

treasure = None
gmsg = None

class htAuth(QDialog):

    def __init__(self):
        super().__init__()
        self.ttext = None
        self.lineedit = None
        self.okButton = None
        self.initUI()

    def setText(self, string):
        self.ttext.setText(string)

    def initUI(self):
        cancelButton = QPushButton("Imma Head Out")
        okButton = QPushButton("Done")
        lineedit = QLineEdit()
        ttext = QTextEdit()
        lab = QLabel("Here is a link to authorize Pyttrick, open it in browser, paste code below, then click Done")

        self.okButton = okButton
        self.lineedit = lineedit
        self.ttext = ttext

        okButton.clicked.connect(self.accept)
        cancelButton.clicked.connect(self.close)
        lineedit.textChanged.connect(self.editChanged)

        ttext.setReadOnly(True)
        qbox = QGridLayout()
        qbox.addWidget(ttext , 0, 0 , 1, 3)
        qbox.addWidget(lab, 1, 0, 1 , 3)
        qbox.addWidget(lineedit, 2, 0, 1 , 3)
        qbox.addWidget(okButton, 3 , 1)
        qbox.addWidget(cancelButton, 3 , 2)

        okButton.setDisabled(True)
        self.setLayout(qbox)
        self.setMinimumWidth(300)
        self.setWindowTitle('Authorize Pyttrick')

    def editChanged(self):
        global gmsg
        gmsg = self.lineedit.text()
        self.okButton.setEnabled(True)

    def showme(self):
        self.adjustSize()
        self.show()

def decrypt_treasure(s):
    return s[::2]

def gen_oauth_request(req_url, ver = None):
    return oauth.Request(method='GET', url=req_url,
                        parameters= { 'oauth_callback': 'oob', 'oauth_nonce': oauth.generate_nonce(),
                                      'oauth_timestamp': oauth.generate_timestamp(), 'oauth_version': '1.0',
                                      'oauth_verifier': ver},
                        is_form_encoded=True)

def ht_authenticate():
    global gmsg
    consumer = oauth.Consumer(decrypt_treasure(CONSUMER_KEY), decrypt_treasure(CONSUMER_SECRET))
    request = gen_oauth_request(REQUEST_TOKEN, None)
    request.sign_request(oauth.SignatureMethod_HMAC_SHA1(), consumer, None)

    with contextlib.closing(urllib.request.urlopen(request.to_url())) as whatever:
        responseData = whatever.read()
        print(responseData)
        token = dict(urllib.parse.parse_qsl(responseData))

        logging.info('TOKEN:', token)
        oauth_token = token[b'oauth_token'].decode('ascii')
        oauth_secret = token[b'oauth_token_secret'].decode('ascii')

        logging.info(oauth_token)
        logging.info(oauth_secret)

        link = "https://chpp.hattrick.org/oauth/authorize.aspx?oauth_token=%s" % oauth_token

        a = htAuth()
        a.setText(link)
        a.show()
        r = a.exec()

        if not r:
            exit(0)
        code = gmsg

    request = gen_oauth_request(ACCESS_TOKEN, code)
    otoken = oauth.Token(oauth_token, oauth_secret)
    otoken.set_verifier(code)

    request.sign_request(oauth.SignatureMethod_HMAC_SHA1(), consumer, otoken)

    try:
        with contextlib.closing(urllib.request.urlopen(request.to_url())) as whatever:
            responseData = whatever.read()
            request_token = dict(urllib.parse.parse_qsl(responseData))
            token = oauth.Token(request_token[b'oauth_token'], request_token[b'oauth_token_secret'])
    except:
        msgBox = QMessageBox()
        msgBox.setIcon(QMessageBox.Information)
        msgBox.setText("Failed to authorize. Exiting.")
        msgBox.setWindowTitle("Fail")
        msgBox.setStandardButtons(QMessageBox.Ok)
        msgBox.exec()
        exit(0)

    my_treasure_key = token.key.decode('ascii')
    my_treasure_secret = token.secret.decode('ascii')
    logging.info('MY_TREEEASUREEEEEE : %s  %s', my_treasure_key, my_treasure_secret)
    return (my_treasure_key, my_treasure_secret)

def load_treasure():
    filejson = "treasure.json"

    if os.path.isfile(filejson):
        with open(filejson, "r") as reader:
            jtreasure = json.load(reader)
            treasure = json.loads(jtreasure)
    else:
        treasure = ht_authenticate()
        enc = json.dumps(treasure)
        with open(filejson, "w") as writer:
            json.dump(enc, writer)
        writer.close()

    return treasure

def ht_gimme(that, ht_opts = []):

    consumer = oauth.Consumer(decrypt_treasure(CONSUMER_KEY), decrypt_treasure(CONSUMER_SECRET))
    ht_enc = urlencode(ht_opts, quote_via=quote_plus)
    url = HT_RESOURCES + "?file=" + that + "&" + ht_enc
    request = gen_oauth_request(url)
    token = oauth.Token(treasure[0].encode('ascii'), treasure[1].encode('ascii'))
    request.sign_request(oauth.SignatureMethod_HMAC_SHA1(), consumer, token)
    with contextlib.closing(urllib.request.urlopen(request.to_url())) as whatever:
        return whatever.read()

class generalTab(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        qgrid = QGridLayout()
        self.setLayout(qgrid)

class squadTab(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        qgrid = QGridLayout()
        self.setLayout(qgrid)

    def update(data):
        pass

class matchesTab(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        qgrid = QGridLayout()
        self.setLayout(qgrid)


class mainWidow(QDialog):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        tabWidget = QTabWidget();
        general_Tab = generalTab()
        squad_Tab = squadTab()
        matches_Tab = matchesTab()
        tabWidget.addTab(general_Tab, "Overview")
        tabWidget.addTab(squad_Tab, "Squad")
        tabWidget.addTab(matches_Tab, "Matches")

        vbox =  QVBoxLayout();
        vbox.addWidget(tabWidget);
        self.setLayout(vbox);
        self.adjustSize()
        self.show()


def main():
    global treasure
    app = QApplication(sys.argv)
    app.setStyleSheet(open('themes/NightStalker.qss').read())
    font = QFont();
    font.setFamily(font.defaultFamily());
    font.setPointSize(font.pointSize() + 2)
    app.setFont(font);

    a = mainWidow()

    treasure = load_treasure()
    whatever =  { 'version' : '1.3'}
    rep = ht_gimme('teamdetails')
    root = ET.fromstring(rep)
    print(rep)
    data = ''
    for x in root.findall('Team'):
        data = x.find('TeamName').text

    print ("Team name: ", data)

    return app.exec()


if __name__ == "__main__":
    main()




