import contextlib
import urllib.request
import oauth2 as oauth
import logging, sys
import json
import os

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

CONSUMER_KEY = 'MF7LcPoUfIfgpMX0QS7Dr3'
CONSUMER_SECRET = 'tw691NKJojQzXwCm3ojAGedYpNLb2EIeQNjVQs3IODw'

def gen_oauth_request(req_url, ver):
    return oauth.Request(method='GET', url=req_url,
                        parameters= { 'oauth_callback': 'oob', 'oauth_nonce': oauth.generate_nonce(),
                                      'oauth_timestamp': oauth.generate_timestamp(), 'oauth_version': '1.0',
                                      'oauth_verifier': ver},
                        is_form_encoded=True)

def ht_authenticate():
    consumer = oauth.Consumer(CONSUMER_KEY, CONSUMER_SECRET)
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

def main():
    load_treasure()

if __name__ == "__main__":
    main()




