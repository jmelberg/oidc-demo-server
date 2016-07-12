from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse
import requests
import json
import jwt as jt
from jose import jwt
from jose import jws

ALLOWED_DOMAINS = ['okta.com', 'oktapreview.com']
DIRTY_KEYS = []
KEYS = []

# Errors

def decode_access_token(auth_header, CLIENT_ID):
    # Get discovery document
    try:
        token = auth_header.split(" ")[1].strip()
        decoded_token = jt.decode(token.decode('utf-8'), verify=False)
        alg = jwt.get_unverified_header(token)['alg']
        kid = jwt.get_unverified_header(token)['kid']

        # Validate the token values
        validated = token_validation(decoded_token, alg, kid, CLIENT_ID)
        
        # Validate keys
        for key in DIRTY_KEYS:
            #Validate the key
            try:
                KEYS.append(jws.verify(token, key, algorithms=[alg]))
            except JWSError:
                return JWSError

        if validated == True:
            # Verify email address is held
            email = ""
            if 'email' in decoded_token:
                # Id token 
                email = decoded_token['email']
            else:
                email = get_user_data(get_discovery_document(decoded_token)['userinfo_endpoint'], auth_header)['email']
            return get_gravitar(email)
        else:
            return validated
    except:
        return {'Error' : 'Could not decode Token'}

    # Default Error
    return {'Error' : 'Unexpected error occurred'}

def token_validation(decoded_token, alg, kid, CLIENT_ID):
    import time

    print decoded_token
    print "****"
    try:
        # Step 1: Verify issuer
        approved = [True for x in ALLOWED_DOMAINS if x in decoded_token['iss']][0]
        if not approved:
            return {'Error' : 'Namespace not allowed'}

        # Step 2: Verify aud contains client_id
        if decoded_token['aud'] != CLIENT_ID:
            return {'Error' : 'Audience does not match client_id'}

        # Call discovery_document
        discovery_document = get_discovery_document(decoded_token)

        # Step 3: Verify signiture of ID Token
        if alg not in discovery_document['id_token_signing_alg_values_supported']:
            return {'Error' : 'Unsupported signing algorithm'}

        # Step 4: Verify expiry time
        if decoded_token['exp'] < int(time.time()):
            return {'Error' : 'Expired token'}

        # Determine if Id token or Access Token
        if 'ID' in decoded_token['jti'][:2]:        
            # Step 5: Verify nonce is present (TODO: Check match to nonce sent in Authentication Request)
            if 'nonce' not in decoded_token:
                return {'Error' : 'Nonce expected'}

            # Step 6: Check auth_time claim value and request re-authentication using prompt=login if too much time passed - omitted
            if 'auth_time' not in decoded_token:
                return {'Error' : 'Expected Authorization Timestamp'}

        # Step 7: Determine JSON Web Key Set
        jwks(discovery_document['jwks_uri'], kid)
        return True

    except:
        return {'Error' : 'Unknown error occured'}

def jwks(url, kid):
    # Get jwks from jwks url in discovery document

    r = requests.get(url)
    jwks = r.json()
    for key in jwks['keys']:
        if kid == key['kid']:
            DIRTY_KEYS.append(key) # Append to master key list


def get_user_data(url, auth_header):
    header = {'Authorization' : auth_header}
    r = requests.get(url=url, headers=header)
    print r.text
    return r.json()

def get_discovery_document(decoded_token):
    url = decoded_token['iss']
   
    # Check if ID token or Access Token, if Access Token, parse
    if "/as/" in url:
        url = url.split('/as/')[0]

    discovery_url = "{}/.well-known/openid-configuration".format(url)
    r = requests.get(url=discovery_url)
    return r.json()

def get_gravitar(email):
    # Calls Gavatar api passing email address
    import urllib
    import hashlib

    default = ""
    gavatar_url = "https://www.gravatar.com/avatar/{}" \
                .format(hashlib.md5(email.lower()).hexdigest() + "?")
    gavatar_url += urllib.urlencode({'d': default, 's':str(200)})
    return {'image' : gavatar_url, 'name' : email}

@csrf_exempt
def index(request):
    # Handles the API request from the mobile applications
    auth_header = request.META['HTTP_AUTHORIZATION']
    
    CLIENT_ID = request.POST['client_id']
    
    if auth_header:
        response = json.dumps(decode_access_token(auth_header, CLIENT_ID))
        print response
        return HttpResponse(response)
    return HttpResponse(json.dumps({'Error' : 'Incorrectly formatted header'}))
