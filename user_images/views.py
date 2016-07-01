from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse
import requests
import json
import jwt as jt
from jose import jwt
from jose import jws


allowed_domains = ['okta.com', 'oktapreview.com']
dirty_keys = []
keys = []

def decode_access_token(auth_header):
    if auth_header is None:
        return {'Error' : 'No Access Token'}

    # Get discovery document
    try:
        token = auth_header.split(" ")[1].strip()
        decoded = jt.decode(token.decode('utf-8'), verify=False)
        alg = jwt.get_unverified_header(token)['alg']
        kid = jwt.get_unverified_header(token)['kid']
        # Validate the access token values
        validated = validate(decoded, alg, kid)
        for key in dirty_keys:
            #Validate the key
            try:
                keys.append(jws.verify(token, key, algorithms=[alg]))
            except JWSError:
                print JWSError

        if validated:
            # Get more information via /userinfo endpoint
            discovery_document = get_discovery_document(decoded)
            user_info = get_user_data(discovery_document['userinfo_endpoint'], auth_header)
            if 'email' in user_info:
                get_gravitar(user_info['email'], user_info['name'])
            else:
                return {'Error' : 'Did not specify email in scope'}
        else:
            return validated
    except:
        return {'Error' : 'Could not decode Access Token'}

    # Default Error
    return {'Error' : 'Unexpected error occurred'}


def jwks(url, kid):
    # Get jwks from jwks url in discovery document
    r = requests.get(url)
    jwks = r.json()
    for key in jwks['keys']:
        if kid == key['kid']:
            dirty_keys.append(key) # Append to master key list

def validate(decoded_token, alg, kid):
    import time
    # Verify iss claim in the ID token matches
    try:
        client_id = decoded_token['client_id']
        aud = decoded_token['aud']

        #Verify exp time
        if decoded_token['exp'] < int(time.time()):
            print "Expired"
            return {'Error' : 'Expired access token'}

        # Verify iss equals aud
        if client_id != aud:
            return {'Error' : 'Client ID does not match'}

        # Call discovery_document
        discovery_document = get_discovery_document(decoded_token)

        # Verify alg
        if alg not in discovery_document['id_token_signing_alg_values_supported']:
            return {'Error' : 'Unsupported signing algorithm'}

        jwks(discovery_document['jwks_uri'], kid)
        return True
    except:
        return {'Error' : 'Unknown error occured'}

def get_user_data(url, auth_header):
    header = {'Authorization' : auth_header}
    r = requests.get(url=url, headers=header)
    return r.json()

def get_discovery_document(decoded_token):
    url = decoded_token['iss']
    valid_domains = [domain for domain in allowed_domains if url not in domain]
    if len(valid_domains) < 1:
        return
    discovery_url = "{}/.well-known/openid-configuration".format(url)
    r = requests.get(url=discovery_url)
    return r.json()

def get_gravitar(email, name):
    # Calls Gavatar api
    import urllib
    import hashlib

    default = ""
    gavatar_url = "https://www.gravatar.com/avatar/{}" \
                .format(hashlib.md5(email.lower()).hexdigest() + "?")
    gavatar_url += urllib.urlencode({'d': default, 's':str(200)})
    return {'image' : gavatar_url, 'name' : name}

@csrf_exempt
def index(request):
    # Handles the API request from the mobile applications
    auth_header = request.META['HTTP_AUTHORIZATION']
    if auth_header:
        return HttpResponse(json.dumps(decode_access_token(str(auth_header))))
    return HttpResponse(json.dumps({'Error' : 'Incorrectly formatted header'}))
