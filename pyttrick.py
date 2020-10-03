import contextlib
import urllib.request
import oauth2 as oauth
import logging, sys
import json
import os
import xml.etree.ElementTree as ET

from urllib.parse import urlencode, quote_plus

logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)

# from hattrick
# Path to protected resources: All CHPP XML files are downloaded from https://chpp.hattrick.org/chppxml.ashx,
# specifying which file is requested using the parameter file=teamdetails (for example). See API Documentation for more info.
# Use GET method for all requests
# Use HMAC-SHA1 to sign all requests
# Always provide oauth_callback in the request to request_token.ashx.
# If your product cannot receive a callback, use oauth_callback=oob

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

def decrypt_treasure(s):
    return s[::2]

def gen_oauth_request(req_url, ver = None):
    return oauth.Request(method='GET', url=req_url,
                        parameters= { 'oauth_callback': 'oob', 'oauth_nonce': oauth.generate_nonce(),
                                      'oauth_timestamp': oauth.generate_timestamp(), 'oauth_version': '1.0',
                                      'oauth_verifier': ver},
                        is_form_encoded=True)

def ht_authenticate():
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

        print("Open in browser:")
        print(f"https://chpp.hattrick.org/oauth/authorize.aspx?oauth_token={oauth_token}")

        print("Paste code here")
        code = input()

    request = gen_oauth_request(ACCESS_TOKEN, code)
    otoken = oauth.Token(oauth_token, oauth_secret)
    otoken.set_verifier(code)

    request.sign_request(oauth.SignatureMethod_HMAC_SHA1(), consumer, otoken)

    with contextlib.closing(urllib.request.urlopen(request.to_url())) as whatever:
        responseData = whatever.read()
        request_token = dict(urllib.parse.parse_qsl(responseData))
        token = oauth.Token(request_token[b'oauth_token'], request_token[b'oauth_token_secret'])

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


def main():
    global treasure
    treasure = load_treasure()

    whatever =  { 'version' : '1.3'}
    rep = ht_gimme('economy', whatever)
    root = ET.fromstring(rep)

    data = ''
    for x in root.findall('Team'):
        data = x.find('TeamName').text

    print ("Team name: ", data)






if __name__ == "__main__":
    main()




