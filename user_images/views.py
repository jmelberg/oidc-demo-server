from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse
import requests
import json
import os

BASE_URL = "https://OKTA_OR_OKTAPREVIEW_URL"

def locate_picture(name_list):
    # Walk main directory and locate image
    print "Searching for: {}".format(" ".join(name_list))

    # Alter user to show returned result:
    for root, subdirs, files in os.walk(os.getcwd()+"/images"):
        for file in files:
            if os.path.splitext(file)[0].lower() == "".join(name_list).lower():
                image = os.path.join(root, file)
                return {'image': image}
    return
def userInfoCall(auth_header):
    # Authenticate user
    okta_url = "{}/oauth2/v1/userinfo".format(BASE_URL)
    print auth_header
    r = requests.get(url=okta_url, headers = {'Authorization' : auth_header})
    result = r.json()

    # parse info form userinfo
    name_list = []
    if result['given_name'] and result['family_name']:
        return locate_picture([result['given_name'], result['family_name']])

@csrf_exempt
def index(request):
    auth_header = request.META['HTTP_AUTHORIZATION']
    if auth_header:
        result = userInfoCall(auth_header)
        if result:
            print "Result: {}".format(result)
            with open(result['image'], 'rb') as f:
                return HttpResponse(f.read(), content_type="image/jpeg")
    print "No match found"
    return HttpResponse(None)
