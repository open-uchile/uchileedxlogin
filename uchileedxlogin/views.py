from django.conf import settings
from django.core.exceptions import ValidationError
from django.contrib.auth import login
from django.contrib.auth.models import User
from django.contrib.sites.shortcuts import get_current_site
from django.db import transaction
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django.views.generic.base import View
from django.http import HttpResponse
from models import EdxLoginUser
from urllib import urlencode
from itertools import cycle
from opaque_keys.edx.keys import CourseKey
from opaque_keys import InvalidKeyError

import json
import requests
import uuid
import unidecode
import logging
import sys
import csv


logger = logging.getLogger(__name__)


class EdxLoginLoginRedirect(View):   

    def get(self, request):
        if request.user.is_authenticated():
            return HttpResponseRedirect('/')
        return HttpResponseRedirect('{}?{}'.format(settings.REQUEST_URL, urlencode(self.service_parameters(request))))

    def service_parameters(self, request):
        """
        store the service parameter for uchileedxlogin.
        """
        parameters = {
            'service': settings.SERVICE,
        }
        return parameters

class EdxLoginCallback(View): 

    def get(self, request):
        ticket = request.GET.get('ticket')
        if ticket is None:
            return HttpResponseRedirect(reverse('uchileedxlogin-login:login'))

        username = self.verify_state(request, ticket)
        if username is None:
            return HttpResponseRedirect(reverse('uchileedxlogin-login:login'))
        try:
            self.login_user(request, username)
        except Exception:
            logger.exception("Error logging "+ username +" - " + ticket)
            return HttpResponseRedirect(reverse('uchileedxlogin-login:login'))
        return HttpResponseRedirect('/')

    def verify_state(self, request, ticket):
        """
            Verify if the ticket is correct
        """
        parameters = {'service': settings.SERVICE, 'ticket': ticket}
        result = requests.get(settings.RESULT_VALIDATE, params=urlencode(parameters), headers={'content-type': 'application/x-www-form-urlencoded', 'User-Agent': 'curl/7.58.0'})
        if result.status_code != 200:
            logger.error("{} {}".format(result.request, result.request.headers))
            raise Exception("Wrong status code {} {}".format(result.status_code, result.text))
        r = result.content.split('\n')
        if r[0] == 'yes':
            return r[1]
        return None

    def login_user(self, request, username):
        """
        Get or create the user and log him in.
        """        
        user_data = self.get_user_data(username)
        user_data['username'] = username
        user = self.get_or_create_user(user_data)
        login(request, user, backend="django.contrib.auth.backends.AllowAllUsersModelBackend",)

    def get_user_data(self, username):
        """
        Get the user data
        """
        parameters = {
            'username': username
        }
        result = requests.get(settings.USER_INFO_URL, params=urlencode(parameters), headers={'content-type': 'application/x-www-form-urlencoded', 'User-Agent': 'curl/7.58.0'})
        return json.loads(result.text)

    def get_user_email(self, rut):
        """
        Get the user email 
        """
        parameters = {
            'rutUsuario': rut
        }
        result = requests.post(settings.USER_EMAIL, data=json.dumps(parameters), headers={'content-type': 'application/json', 'Authorization': 'Basic ZGVzYTpkZXNh'})
        data = json.loads(result.text)
        return str(data['usuarioLdap']['mail'])

    def get_or_create_user(self, user_data):
        """
        Get or create the user given the user data.
        If the user exists, update the email address in case the users has updated it.
        """
        mail = self.get_user_email(user_data['rut'])
        try:
            clave_user = EdxLoginUser.objects.get(run=user_data['rut'])
            user = clave_user.user
            
            if user.email != mail and not User.objects.filter(email=mail).exists():
                user.email = mail
                user.save()
            return user
        except EdxLoginUser.DoesNotExist:
            with transaction.atomic():
                user = self.create_user_by_data(user_data, mail)
                clave_unica = EdxLoginUser.objects.create(
                    user=user,
                    run=user_data['rut']
                )                
            return user

    def create_user_by_data(self, user_data, mail):
        """
        Create the user by the Django model
        """
        from student.forms import AccountCreationForm
        from student.helpers import do_create_account

        # Check and remove email if its already registered
        user_data['email'] = mail
        if User.objects.filter(email=mail).exists():
            user_data['email'] = str(uuid.uuid4()) + '@invalid.invalid'

        form = AccountCreationForm(
            data={
                "username": user_data['username'].replace('.','_'),
                "email": user_data['email'],
                "password": "invalid",  # Temporary password
                "name": user_data['nombreCompleto'],
            },
            tos_required=False,
        )

        user, _, reg = do_create_account(form)
        reg.activate()
        reg.save()
        from student.models import create_comments_service_user
        create_comments_service_user(user)

        # Invalidate the user password, as it will be never be used
        user.set_unusable_password()
        user.save()

        return user

    def fetch_json(self, url):
        response = requests.get(url)
        return response.json()
