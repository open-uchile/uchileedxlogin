#!/usr/bin/env python
# -- coding: utf-8 --

from django.conf import settings
from django.core.exceptions import ValidationError
from django.contrib.auth import login, logout
from django.contrib.auth.models import User
from django.contrib.sites.shortcuts import get_current_site
from django.db import transaction
from django.http import HttpResponseRedirect, HttpResponseForbidden, Http404
from django.shortcuts import render
from django.urls import reverse
from django.views.generic.base import View
from django.http import HttpResponse
from .models import EdxLoginUser, EdxLoginUserCourseRegistration
from .email_tasks import enroll_email
from urllib.parse import urlencode
from itertools import cycle
from opaque_keys.edx.keys import CourseKey
from opaque_keys import InvalidKeyError
from lms.djangoapps.courseware.courses import get_course_by_id, get_course_with_access
from lms.djangoapps.courseware.access import has_access
from common.djangoapps.util.json_request import JsonResponse, JsonResponseBadRequest
import json
import requests
import uuid
import unidecode
import logging
import sys
import unicodecsv as csv
import re
from django.contrib.auth.base_user import BaseUserManager
logger = logging.getLogger(__name__)
regex = r'^(([^<>()\[\]\.,;:\s@\"]+(\.[^<>()\[\]\.,;:\s@\"]+)*)|(\".+\"))@(([^<>()[\]\.,;:\s@\"]+\.)+[^<>()[\]\.,;:\s@\"]{2,})$'
regex_names = r'^[A-Za-z\s\_]+$'


def require_post_action():
    """
    Checks for required parameters or renders a 400 error.
    (decorator with arguments)

    `args` is a *list of required POST parameter names.
    `kwargs` is a **dict of required POST parameter names
        to string explanations of the parameter
    """
    def decorator(func):  # pylint: disable=missing-docstring
        def wrapped(*args, **kwargs):  # pylint: disable=missing-docstring
            request = args[1]
            action = request.POST.get("action", "")
            error_response_data = {
                'error': 'Missing required query parameter(s)',
                'parameters': ["action"],
                'info': {"action": action},
            }
            if action in ["enroll", "unenroll", "staff_enroll"]:
                return func(*args, **kwargs)
            else:
                return JsonResponse(error_response_data, status=400)

        return wrapped
    return decorator


class Content(object):
    def get_user_data(self, username):
        """
        Get the user data
        """
        parameters = {
            'username': username
        }
        result = requests.get(
            settings.EDXLOGIN_USER_INFO_URL,
            params=urlencode(parameters),
            headers={
                'content-type': 'application/x-www-form-urlencoded',
                'User-Agent': 'curl/7.58.0'})
        if result.status_code != 200:
            logger.error(
                "{} {}".format(
                    result.request,
                    result.request.headers))
            raise Exception(
                "Wrong username {} {}".format(
                    result.status_code, username))
        return json.loads(result.text)

    def get_user_email(self, rut):
        """
        Get the user email
        """
        parameters = {
            'rut': rut
        }
        result = requests.post(
            settings.EDXLOGIN_USER_EMAIL,
            data=json.dumps(parameters),
            headers={
                'content-type': 'application/json'})
        if result.status_code == 200:
            data = json.loads(result.text)
            if 'emails' in data:
                return self.verify_email_principal(data)
        return 'null'

    def verify_email_principal(self, data):
        """
            Verify if data have principal email
        """
        for mail in data['emails']:
            if mail['nombreTipoEmail'] == 'PRINCIPAL':
                if mail['email'] is not None and re.match(
                        regex, mail['email'].lower()):
                    if not User.objects.filter(email=mail['email']).exists():
                        return mail['email']

        return self.verify_email_alternativo(data)

    def verify_email_alternativo(self, data):
        """
            Verify if data have alternative email
        """
        for mail in data['emails']:
            if mail['nombreTipoEmail'] == 'ALTERNATIVO':
                if mail['email'] is not None and re.match(
                        regex, mail['email'].lower()):
                    if not User.objects.filter(email=mail['email']).exists():
                        return mail['email']

        return 'null'

    def get_or_create_user(self, user_data):
        """
        Get or create the user given the user data.
        If the user exists, update the email address in case the users has updated it.
        """
        try:
            clave_user = EdxLoginUser.objects.get(run=user_data['rut'])
            return clave_user
        except EdxLoginUser.DoesNotExist:
            with transaction.atomic():
                user_data['email'] = self.get_user_email(user_data['rut'])
                user = self.create_user_by_data(user_data)
                edxlogin_user = EdxLoginUser.objects.create(
                    user=user,
                    have_sso=True,
                    run=user_data['rut']
                )
            return edxlogin_user

    def create_user_by_data(self, user_data):
        """
        Create the user by the Django model
        """
        from openedx.core.djangoapps.user_authn.views.registration_form import AccountCreationForm
        from common.djangoapps.student.helpers import do_create_account
        # Check and remove email if its already registered
        user_pass = "invalid" if 'pass' not in user_data else user_data['pass']  # Temporary password
        if user_data['email'] == 'null':
            user_data['email'] = str(uuid.uuid4()) + '@invalid.invalid'
        form = AccountCreationForm(
            data={
                "username": self.generate_username(user_data),
                "email": user_data['email'],
                "password": user_pass,
                "name": user_data['nombreCompleto'],
            },
            tos_required=False,
            ignore_email_blacklist=True
        )
        user, _, reg = do_create_account(form)
        reg.activate()
        reg.save()
        #from common.djangoapps.student.models import create_comments_service_user
        #create_comments_service_user(user)

        if 'pass' not in user_data:
            # Invalidate the user password, as it will be never be used
            user.set_unusable_password()
            user.save()

        return user

    def generate_username(self, user_data):
        """
        Generate an username for the given user_data
        This generation will be done as follow:
        1. return first_name[0] + "_" + last_name[0]
        2. return first_name[0] + "_" + last_name[0] + "_" + last_name[1..N][0..N]
        3. return first_name[0] + "_" first_name[1..N][0..N] + "_" + last_name[0]
        4. return first_name[0] + "_" first_name[1..N][0..N] + "_" + last_name[1..N][0..N]
        5. return first_name[0] + "_" + last_name[0] + N
        """
        if 'apellidoPaterno' not in user_data or 'apellidoMaterno' not in user_data or 'nombres' not in user_data:
            aux_username = unidecode.unidecode(user_data['nombreCompleto'].lower())
            aux_username = re.sub(r'[^a-zA-Z0-9\_]', ' ', aux_username)
            aux_username = aux_username.split(" ")
            if len(aux_username) > 1:
                i = int(len(aux_username)/2)
                aux_first_name = aux_username[0:i]
                aux_last_name = aux_username[i:]
            else:
                if User.objects.filter(username=aux_username[0]).exists():
                    for i in range(1, 10000):
                        name_tmp = aux_username[0] + str(i)
                        if not User.objects.filter(username=name_tmp).exists():
                            return name_tmp
                else:
                    return aux_username[0]
        else:
            aux_last_name = ((user_data['apellidoPaterno'] or '') +
                            " " + (user_data['apellidoMaterno'] or '')).strip()
            aux_last_name = unidecode.unidecode(aux_last_name)
            aux_last_name = re.sub(r'[^a-zA-Z0-9\_]', ' ', aux_last_name)
            aux_last_name = aux_last_name.split(" ")
            aux_first_name = unidecode.unidecode(user_data['nombres'])
            aux_first_name = re.sub(r'[^a-zA-Z0-9\_]', ' ', aux_first_name)
            aux_first_name = aux_first_name.split(" ")

        first_name = aux_first_name
        last_name = aux_last_name

        # 1.
        test_name = first_name[0] + "_" + last_name[0]
        if len(test_name) <= EdxLoginCallback.USERNAME_MAX_LENGTH and not User.objects.filter(
                username=test_name).exists():
            return test_name

        # 2.
        for i in range(len(last_name[1:])):
            test_name = test_name + "_"
            for j in range(len(last_name[i + 1])):
                test_name = test_name + last_name[i + 1][j]
                if len(test_name) > EdxLoginCallback.USERNAME_MAX_LENGTH:
                    break
                if not User.objects.filter(username=test_name).exists():
                    return test_name

        # 3.
        first_name_temp = first_name[0]
        for i in range(len(first_name[1:])):
            first_name_temp = first_name_temp + "_"
            for j in range(len(first_name[i + 1])):
                first_name_temp = first_name_temp + first_name[i + 1][j]
                test_name = first_name_temp + "_" + last_name[0]
                if len(test_name) > EdxLoginCallback.USERNAME_MAX_LENGTH:
                    break
                if not User.objects.filter(username=test_name).exists():
                    return test_name

        # 4.
        first_name_temp = first_name[0]
        for first_index in range(len(first_name[1:])):
            first_name_temp = first_name_temp + "_"
            for first_second_index in range(len(first_name[first_index + 1])):
                first_name_temp = first_name_temp + \
                    first_name[first_index + 1][first_second_index]
                test_name = first_name_temp + "_" + last_name[0]
                if len(test_name) > EdxLoginCallback.USERNAME_MAX_LENGTH:
                    break
                for second_index in range(len(last_name[1:])):
                    test_name = test_name + "_"
                    for second_second_index in range(
                            len(last_name[second_index + 1])):
                        test_name = test_name + \
                            last_name[second_index + 1][second_second_index]
                        if len(test_name) > EdxLoginCallback.USERNAME_MAX_LENGTH:
                            break
                        if not User.objects.filter(
                                username=test_name).exists():
                            return test_name

        # 5.
        # Make sure we have space to add the numbers in the username
        test_name = first_name[0] + "_" + last_name[0]
        test_name = test_name[0:(EdxLoginCallback.USERNAME_MAX_LENGTH - 5)]
        if test_name[-1] == '_':
            test_name = test_name[:-1]
        for i in range(1, 10000):
            name_tmp = test_name + str(i)
            if not User.objects.filter(username=name_tmp).exists():
                return name_tmp

        # Username cant be generated
        raise Exception("Error generating username for name {}".format())


class ContentStaff(object):
    def validarRut(self, rut):
        """
            Verify if the 'rut' is valid
        """
        rut = rut.upper()
        rut = rut.replace("-", "")
        rut = rut.replace(".", "")
        rut = rut.strip()
        aux = rut[:-1]
        dv = rut[-1:]

        revertido = list(map(int, reversed(str(aux))))
        factors = cycle(list(range(2, 8)))
        s = sum(d * f for d, f in zip(revertido, factors))
        res = (-s) % 11

        if str(res) == dv:
            return True
        elif dv == "K" and res == 10:
            return True
        else:
            return False

    def validate_course(self, id_curso):
        """
            Verify if course.id exists
        """
        from openedx.core.djangoapps.content.course_overviews.models import CourseOverview
        try:
            aux = CourseKey.from_string(id_curso)
            return CourseOverview.objects.filter(id=aux).exists()
        except InvalidKeyError:
            return False

    def validate_data(self, user, lista_run, context, force):
        """
            Verify if the data if valid
        """
        run_malos = ""
        original_ruts = []
        duplicate_ruts = []
        original_courses = []
        duplicate_courses = []
        # validacion de los run
        for run in lista_run:
            try:
                if run[0] == 'P':
                    if 5 > len(run[1:]) or len(run[1:]) > 20:
                        run_malos += run + " - "
                elif run[0:2] == 'CG':
                    if len(run) != 10:
                        run_malos += run + " - "
                else:
                    if not self.validarRut(run):
                        run_malos += run + " - "
                if run in original_ruts:
                    duplicate_ruts.append(run)
                else:
                    original_ruts.append(run)
            except Exception:
                run_malos += run + " - "

        run_malos = run_malos[:-3]

        # validaciones de otros campos
        # si existe run malo
        if run_malos != "":
            context['run_malos'] = run_malos
        if len(duplicate_ruts) > 0:
            context['duplicate_ruts'] = duplicate_ruts
        # valida curso
        if context['curso'] == "":
            context['curso2'] = ''
        # valida si existe el curso
        else:
            list_course = context['curso'].split('\n')
            list_course = [course_id.strip() for course_id in list_course]
            list_course = [course_id for course_id in list_course if course_id]
            for course_id in list_course:
                if course_id in original_courses:
                    duplicate_courses.append(course_id)
                else:
                    original_courses.append(course_id)
                if not self.validate_course(course_id):
                    if 'error_curso' not in context:
                        context['error_curso'] = [course_id]
                    else:
                        context['error_curso'].append(course_id)
                    logger.error("EdxLoginStaff - Course dont exists, user: {}, course_id: {}".format(user.id, course_id))
            if 'error_curso' not in context:
                for course_id in list_course:
                    if not self.validate_user(user, course_id):
                        if 'error_permission' not in context:
                            context['error_permission'] = [course_id]
                        else:
                            context['error_permission'].append(course_id)
                        logger.error("EdxLoginStaff - User dont have permission, user: {}, course_id: {}".format(user.id, course_id))
        if len(duplicate_courses) > 0:
            context['duplicate_courses'] = duplicate_courses
        # si no se ingreso run
        if not lista_run:
            context['no_run'] = ''

        # si el modo es incorrecto
        if not context['modo'] in [
                x[0] for x in EdxLoginUserCourseRegistration.MODE_CHOICES]:
            context['error_mode'] = ''

        # si la accion es incorrecto
        if not context['action'] in [
                "enroll",
                "unenroll",
                "staff_enroll"]:
            context['error_action'] = ''
        return context

    def enroll_course(self, edxlogin_user, course, enroll, mode):
        """
        Enroll the user in the pending courses, removing the enrollments when
        they are applied.
        """
        from common.djangoapps.student.models import CourseEnrollment, CourseEnrollmentAllowed

        if enroll:
            CourseEnrollment.enroll(
                edxlogin_user.user,
                CourseKey.from_string(course),
                mode=mode)
        else:
            CourseEnrollmentAllowed.objects.create(
                course_id=CourseKey.from_string(course),
                email=edxlogin_user.user.email,
                user=edxlogin_user.user)

    def is_course_staff(self, user, course_id):
        """
            Verify if the user is staff course
        """
        try:
            course_key = CourseKey.from_string(course_id)
            course = get_course_with_access(user, "load", course_key)

            return bool(has_access(user, 'staff', course))
        except Exception:
            return False

    def is_instructor(self, user, course_id):
        """
            Verify if the user is instructor
        """
        try:
            course_key = CourseKey.from_string(course_id)
            course = get_course_with_access(user, "load", course_key)

            return bool(has_access(user, 'instructor', course))
        except Exception:
            return False

    def validate_user(self, user, course_id):
        """
            Verify if the user have permission
        """
        access = False
        if not user.is_anonymous:
            if user.has_perm('uchileedxlogin.uchile_instructor_staff'):
                if user.is_staff:
                    access = True
                if self.is_instructor(user, course_id):
                    access = True
                if self.is_course_staff(user, course_id):
                    access = True
        return access

    def get_username(self, run):
        """
        Get username
        """

        parameters = {
            'rutUsuario': run
        }
        result = requests.post(
            settings.EDXLOGIN_USERNAME,
            data=json.dumps(parameters),
            headers={
                'content-type': 'application/json'})
        if result.status_code != 200:
            logger.error(
                "{} {}".format(
                    result.request,
                    result.request.headers))
            raise Exception("Wrong run {} {}".format(result.status_code, run))

        data = json.loads(result.text)
        username = ""
        if "cuentascorp" in data and len(data["cuentascorp"]) > 0:
            email = data["cuentascorp"]
            for name in email:
                if name["tipoCuenta"] == "CUENTA PASAPORTE":
                    username = name["cuentaCorp"] or ""
                    break
        return username

class EdxLoginLoginRedirect(View):
    def get(self, request):
        redirect_url = request.GET.get('next', "/")
        if request.user.is_authenticated:
            return HttpResponseRedirect(redirect_url)

        return HttpResponseRedirect(
            '{}?{}'.format(
                settings.EDXLOGIN_REQUEST_URL,
                urlencode(
                    self.service_parameters(request))))

    def service_parameters(self, request):
        """
        store the service parameter for uchileedxlogin.
        """

        parameters = {
            'service': EdxLoginLoginRedirect.get_callback_url(request),
            'renew': 'true'
        }
        return parameters

    @staticmethod
    def get_callback_url(request):
        """
        Get the callback url
        """
        import base64
        redirect_url = base64.b64encode(request.GET.get('next', "/").encode("utf-8")).decode("utf-8")
        url = request.build_absolute_uri(
            reverse('uchileedxlogin-login:callback'))
        return '{}?next={}'.format(url, redirect_url)


class EdxLoginCallback(View, Content):
    USERNAME_MAX_LENGTH = 30

    def get(self, request):
        import base64
        from openedx.core.djangoapps.user_authn.utils import is_safe_login_or_logout_redirect

        ticket = request.GET.get('ticket')
        redirect_url = base64.b64decode(
            request.GET.get(
                'next', "Lw==")).decode('utf-8')
        if not is_safe_login_or_logout_redirect(redirect_url, request.get_host(), None, False):
            redirect_url = "/"
        error_url = reverse('uchileedxlogin-login:login')

        if ticket is None:
            logger.exception("error ticket")
            return HttpResponseRedirect(
                '{}?next={}'.format(
                    error_url, redirect_url))

        username = self.verify_state(request, ticket)
        if username is None:
            logger.exception("Error username ")
            return HttpResponseRedirect(
                '{}?next={}'.format(
                    error_url, redirect_url))
        try:
            self.login_user(request, username)
        except Exception:
            logger.exception("Error logging " + username + " - " + ticket)
            return HttpResponseRedirect(
                '{}?next={}'.format(
                    error_url, redirect_url))
        return HttpResponseRedirect(redirect_url)

    def verify_state(self, request, ticket):
        """
            Verify if the ticket is correct
        """
        url = request.build_absolute_uri(
            reverse('uchileedxlogin-login:callback'))
        parameters = {
            'service': '{}?next={}'.format(
                url,
                request.GET.get('next')),
            'ticket': ticket,
            'renew': 'true'}
        result = requests.get(
            settings.EDXLOGIN_RESULT_VALIDATE,
            params=urlencode(parameters),
            headers={
                'content-type': 'application/x-www-form-urlencoded',
                'User-Agent': 'curl/7.58.0'})
        if result.status_code == 200:
            r = result.content.decode('utf-8').split('\n')
            if r[0] == 'yes':
                return r[1]

        return None

    def login_user(self, request, username):
        """
        Get or create the user and log him in.
        """
        user_data = self.get_user_data(username)
        user_data['username'] = username
        edxlogin_user = self.get_or_create_user(user_data)
        if not edxlogin_user.have_sso:
            edxlogin_user.have_sso = True
            edxlogin_user.save()
        self.enroll_pending_courses(edxlogin_user)
        if request.user.is_anonymous or request.user.id != edxlogin_user.user.id:
            logout(request)
            login(
                request,
                edxlogin_user.user,
                backend="django.contrib.auth.backends.AllowAllUsersModelBackend",
            )

    def enroll_pending_courses(self, edxlogin_user):
        """
        Enroll the user in the pending courses, removing the enrollments when
        they are applied.
        """
        from common.djangoapps.student.models import CourseEnrollment, CourseEnrollmentAllowed
        registrations = EdxLoginUserCourseRegistration.objects.filter(
            run=edxlogin_user.run)
        for item in registrations:
            if item.auto_enroll:
                CourseEnrollment.enroll(
                    edxlogin_user.user, item.course, mode=item.mode)
            else:
                CourseEnrollmentAllowed.objects.create(
                    course_id=item.course,
                    email=edxlogin_user.user.email,
                    user=edxlogin_user.user)
        registrations.delete()


class EdxLoginStaff(View, Content, ContentStaff):
    """
        Enroll/force enroll/unenroll user
    """
    def get(self, request):
        if not request.user.is_anonymous:
            if request.user.has_perm('uchileedxlogin.uchile_instructor_staff') or request.user.is_staff:
                context = {'runs': '', 'auto_enroll': True, 'modo': 'audit', 'curso':''}
                return render(request, 'edxlogin/staff.html', context)
            else:
                logger.error("User dont have permission or is not staff, user: {}".format(request.user))
        else:
            logger.error("User is Anonymous")
        raise Http404()

    @require_post_action()
    def post(self, request):
        if not request.user.is_anonymous:
            if request.user.has_perm('uchileedxlogin.uchile_instructor_staff') or request.user.is_staff:
                action = request.POST.get("action", "")
                lista_run = request.POST.get("runs", "").split('\n')
                # limpieza de los run ingresados
                lista_run = [run.upper() for run in lista_run]
                lista_run = [run.replace("-", "") for run in lista_run]
                lista_run = [run.replace(".", "") for run in lista_run]
                lista_run = [run.strip() for run in lista_run]
                lista_run = [run for run in lista_run if run]

                # verifica si el checkbox de auto enroll fue seleccionado
                enroll = False
                if request.POST.getlist("enroll"):
                    enroll = True

                # verifica si el checkbox de forzar creacion de usuario fue
                # seleccionado
                force = False
                if request.POST.getlist("force"):
                    force = True

                context = {
                    'runs': request.POST.get('runs'),
                    'action': action,
                    'curso': request.POST.get(
                        "course",
                        ""),
                    'auto_enroll': enroll,
                    'modo': request.POST.get(
                        "modes",
                        None)}
                # validacion de datos
                context = self.validate_data(request.user, lista_run, context, force)
                # retorna si hubo al menos un error
                if len(context) > 5 and action not in ["enroll", "unenroll"]:
                    return render(request, 'edxlogin/staff.html', context)
                if len(context) > 5 and action in ["enroll", "unenroll"]:
                    return JsonResponse(context)

                list_course = context['curso'].split('\n')
                list_course = [course_id.strip() for course_id in list_course]
                list_course = [course_id for course_id in list_course if course_id]
                if action in ["enroll", "staff_enroll"]:
                    context = self.enroll_or_create_user(
                        list_course, context['modo'], lista_run, force, enroll)
                    if action in ["enroll"]:
                        return JsonResponse(context)
                    return render(request, 'edxlogin/staff.html', context)

                elif action == "unenroll":
                    context = self.unenroll_user(list_course, lista_run)
                    return JsonResponse(context)
            else:
                logger.error("User dont have permission or is not staff, user: {}".format(request.user))
                raise Http404()
        else:
            logger.error("EdxLoginStaff - User is Anonymous")
            raise Http404()

    def enroll_or_create_user(self, course_ids, mode, lista_run, force, enroll):
        """
            Enroll/force enroll users
        """
        run_saved_force = ""
        run_saved_force_no_auto = ""
        run_saved_pending = ""
        run_saved_enroll = ""
        run_saved_enroll_no_auto = ""
        # guarda el form
        with transaction.atomic():
            for run in lista_run:
                while len(run) < 10 and 'P' != run[0] and 'CG' != run[0:2]:
                    run = "0" + run
                try:
                    edxlogin_user = EdxLoginUser.objects.get(run=run)
                    for course_id in course_ids:
                        self.enroll_course(
                            edxlogin_user, course_id, enroll, mode)
                    if enroll:
                        run_saved_enroll += edxlogin_user.user.username + " - " + run + " / "
                    else:
                        run_saved_enroll_no_auto += edxlogin_user.user.username + " - " + run + " / "
                except EdxLoginUser.DoesNotExist:
                    edxlogin_user = None
                    if force:
                        edxlogin_user = self.force_create_user(run)
                    if edxlogin_user:
                        for course_id in course_ids:
                            self.enroll_course(
                                edxlogin_user, course_id, enroll, mode)
                        if enroll:
                            run_saved_force += edxlogin_user.user.username + " - " + run + " / "
                        else:
                            run_saved_force_no_auto += edxlogin_user.user.username + " - " + run + " / "
                    else:
                        for course_id in course_ids:
                            registro = EdxLoginUserCourseRegistration()
                            registro.run = run
                            registro.course = course_id
                            registro.mode = mode
                            registro.auto_enroll = enroll
                            registro.save()
                        run_saved_pending += run + " - "
        run_saved = {
            'run_saved_force': run_saved_force[:-3],
            'run_saved_pending': run_saved_pending[:-3],
            'run_saved_enroll': run_saved_enroll[:-3],
            'run_saved_enroll_no_auto': run_saved_enroll_no_auto[:-3],
            'run_saved_force_no_auto': run_saved_force_no_auto[:-3]
        }
        return {
            'runs': '',
            'curso': '',
            'auto_enroll': True,
            'modo': 'audit',
            'saved': 'saved',
            'run_saved': run_saved}

    def unenroll_user(self, course_ids, lista_run):
        """
            Unenroll user
        """
        from common.djangoapps.student.models import CourseEnrollment, CourseEnrollmentAllowed

        course_keys = [CourseKey.from_string(course_id) for course_id in course_ids]
        lista_run_format = []
        run_unenroll_pending = []
        run_unenroll_allowed = []
        run_unenroll_enroll = []
        for run in lista_run:
            while len(run) < 10 and 'P' != run[0] and 'CG' != run[0:2]:
                run = "0" + run
            lista_run_format.append(run)

        with transaction.atomic():
            edxlogin_users = EdxLoginUser.objects.filter(run__in=lista_run_format)
            #unenroll EdxLoginUserCourseRegistration
            registrations = EdxLoginUserCourseRegistration.objects.filter(
                run__in=lista_run_format, course__in=course_keys)
            if registrations:
                run_unenroll_pending = [x.run for x in registrations]
                registrations.delete()
            #unenroll CourseEnrollmentAllowed
            enrollmentAllowed = CourseEnrollmentAllowed.objects.filter(
                course_id__in=course_keys, user__edxloginuser__in=edxlogin_users)
            if enrollmentAllowed:
                run_unenroll_allowed = [x.user.edxloginuser.run for x in enrollmentAllowed]
                enrollmentAllowed.delete()
            #unenroll CourseEnrollment
            enrollment = CourseEnrollment.objects.filter(user__edxloginuser__in=edxlogin_users, course_id__in=course_keys)
            if enrollment:
                run_unenroll_enroll = [x.user.edxloginuser.run for x in enrollment]
                enrollment.update(is_active=0)
        aux_run_unenroll = run_unenroll_pending
        aux_run_unenroll.extend(run_unenroll_allowed)
        aux_run_unenroll.extend(run_unenroll_enroll)
        run_unenroll = []
        for i in aux_run_unenroll:
            if i not in run_unenroll:
                run_unenroll.append(i)
        run_unenroll_no_exists = [x for x in lista_run_format if x not in run_unenroll]
        return {
            'runs': '',
            'auto_enroll': True,
            'modo': 'honor',
            'saved': 'unenroll',
            'run_unenroll_no_exists': run_unenroll_no_exists,
            'run_unenroll': run_unenroll}

    def force_create_user(self, run):
        """
            Get user data and create the user
        """
        try:
            username = self.get_username(run)
            user_data = self.get_user_data(username)
            user_data['username'] = username
            edxlogin_user = self.get_or_create_user(user_data)
            return edxlogin_user
        except Exception:
            return None


class EdxLoginExport(View):
    """
        Export all edxlogin users to csv file
    """

    def get(self, request):
        data = []
        users_edxlogin = EdxLoginUser.objects.all().order_by(
            'user__username').values('run', 'user__username', 'user__email')

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="users.csv"'

        writer = csv.writer(
            response,
            delimiter=';',
            dialect='excel',
            encoding='utf-8')
        data.append([])
        data[0].extend(['Run', 'Username', 'Email'])
        i = 1
        for user in users_edxlogin:
            data.append([])
            data[i].extend(
                [user['run'], user['user__username'], user['user__email']])
            i += 1
        writer.writerows(data)

        return response

class EdxLoginExternal(View, Content, ContentStaff):
    """
        Enroll external user
    """
    def get(self, request):
        if not request.user.is_anonymous:
            if request.user.has_perm('uchileedxlogin.uchile_instructor_staff') or request.user.is_staff:
                context = {'datos': '', 'auto_enroll': True, 'modo': 'honor', 'send_email': True, 'curso': ''}
                return render(request, 'edxlogin/external.html', context)
            else:
                logger.error("EdxLoginExternal - User dont have permission or is not staff, user: {}".format(request.user))
        else:
            logger.error("EdxLoginExternal - User is Anonymous")
        raise Http404()

    def post(self, request):
        if not request.user.is_anonymous:
            if request.user.has_perm('uchileedxlogin.uchile_instructor_staff') or request.user.is_staff:
                lista_data = request.POST.get("datos", "").split('\n')
                # limpieza de los datos ingresados
                lista_data = [run.strip() for run in lista_data]
                lista_data = [run for run in lista_data if run]
                lista_data = [d.split(",") for d in lista_data]
                # verifica si el checkbox de auto enroll fue seleccionado
                enroll = False
                if request.POST.getlist("enroll"):
                    enroll = True
                # verifica si el checkbox de send_email fue seleccionado
                send_email = False
                if request.POST.getlist("send_email"):
                    send_email = True
                context = {
                    'datos': request.POST.get('datos'),
                    'curso': request.POST.get("course", ""),
                    'auto_enroll': enroll,
                    'send_email': send_email,
                    'modo': request.POST.get("modes", None)}
                # validacion de datos
                context = self.validate_data_external(request.user, lista_data, context)
                # retorna si hubo al menos un error
                if len(context) > 5:
                    return render(request, 'edxlogin/external.html', context)
                list_course = context['curso'].split('\n')
                list_course = [course_id.strip() for course_id in list_course]
                list_course = [course_id for course_id in list_course if course_id]

                lista_saved, lista_not_saved = self.enroll_create_user(
                    list_course, context['modo'], lista_data, enroll)

                login_url = request.build_absolute_uri('/login')
                helpdesk_url = request.build_absolute_uri('/contact_form')
                email_saved = []
                courses = [get_course_by_id(CourseKey.from_string(course_id)) for course_id in list_course]
                courses_name = ''
                for course in courses:
                    courses_name = courses_name + course.display_name_with_default + ', '
                courses_name = courses_name[:-2]
                for email in lista_saved:
                    if send_email:
                        if email['email_d'] != email['email_o']:
                            enroll_email.delay(email['password'], email['email_d'], courses_name, email['sso'], email['exists'], login_url, email['nombreCompleto'], helpdesk_url, email['email_o'])
                        else:
                            enroll_email.delay(email['password'], email['email_d'], courses_name, email['sso'], email['exists'], login_url, email['nombreCompleto'], helpdesk_url, '')
                    aux = email
                    aux.pop('password', None)
                    email_saved.append(aux)

                context = {
                    'datos': '',
                    'auto_enroll': True,
                    'send_email': True,
                    'curso': '',
                    'modo': 'honor',
                    'action_send': send_email
                }
                if len(email_saved) > 0:
                    context['lista_saved'] = email_saved
                if len(lista_not_saved) > 0:
                    context['lista_not_saved'] = lista_not_saved
                return render(request, 'edxlogin/external.html', context)
            else:
                logger.error("EdxLoginExternal - User dont have permission or is not staff, user: {}".format(request.user))
                raise Http404()
        else:
            logger.error("EdxLoginExternal - User is Anonymous")
            raise Http404()

    def validate_data_external(self, user, lista_data, context):
        """
            Validate Data
        """
        wrong_data = []
        duplicate_data = [[],[]]
        original_data = [[],[]]
        duplicate_courses = []
        original_courses = []
        # si no se ingreso datos
        if not lista_data:
            logger.error("EdxLoginExternal - Empty Data, user: {}".format(user.id))
            context['no_data'] = ''
        if len(lista_data) > 50:
            logger.error("EdxLoginExternal - data limit is 50, length data: {} user: {}".format(len(lista_data),user.id))
            context['limit_data'] = ''
        else:
            for data in lista_data:
                data = [d.strip() for d in data]
                if len(data) == 1 or len(data)>3:
                    data.append("")
                    data.append("")
                    wrong_data.append(data)
                    logger.error("EdxLoginExternal - Wrong Data, only one or four++ parameters, user: {}, wrong_data: {}".format(user.id, wrong_data))
                else:
                    if len(data) == 2:
                        data.append("")
                    if data[0] != "" and data[1] != "":
                        aux_name = unidecode.unidecode(data[0].lower())
                        aux_name = re.sub(r'[^a-zA-Z0-9\_]', ' ', aux_name)
                        if not re.match(regex_names, aux_name):
                            logger.error("EdxLoginExternal - Wrong Name, not allowed specials characters, user: {}, wrong_data: {}".format(user.id, wrong_data))
                            wrong_data.append(data)
                        elif not re.match(regex, data[1].lower()):
                            logger.error("EdxLoginExternal - Wrong Email {}, user: {}, wrong_data: {}".format(data[1].lower(), user.id, wrong_data))
                            wrong_data.append(data)
                        elif data[2] != "" and not self.validarRutAllType(data[2]):
                            logger.error("EdxLoginExternal - Wrong Rut {}, user: {}, wrong_data: {}".format(data[2], user.id, wrong_data))
                            wrong_data.append(data)
                        elif data[1] in original_data[0] or (data[2] != '' and data[2] in original_data[1]):
                            if data[1] in original_data[0]:
                                duplicate_data[0].append(data[1])
                            if data[2] != '' and data[2] in original_data[1]:
                                duplicate_data[1].append(data[2])
                        else:
                            original_data[0].append(data[1])
                            if data[2] != '':
                                original_data[1].append(data[2])
                    else:
                        wrong_data.append(data)
        if len(wrong_data) > 0:
            logger.error("EdxLoginExternal - Wrong Data, user: {}, wrong_data: {}".format(user.id, wrong_data))
            context['wrong_data'] = wrong_data
        if len(duplicate_data[0]) > 0:
            logger.error("EdxLoginExternal - Duplicate Email, user: {}, duplicate_data: {}".format(user.id, duplicate_data[0]))
            context['duplicate_email'] = duplicate_data[0]
        if len(duplicate_data[1]) > 0:
            logger.error("EdxLoginExternal - Duplicate Rut, user: {}, duplicate_data: {}".format(user.id, duplicate_data[1]))
            context['duplicate_rut'] = duplicate_data[1]
        # valida curso
        if context['curso'] == "":
            logger.error("EdxLoginExternal - Empty course, user: {}".format(user.id))
            context['curso2'] = ''

        # valida si existe el curso
        else:
            list_course = context['curso'].split('\n')
            list_course = [course_id.strip() for course_id in list_course]
            list_course = [course_id for course_id in list_course if course_id]
            for course_id in list_course:
                if course_id in original_courses:
                    duplicate_courses.append(course_id)
                else:
                    original_courses.append(course_id)
                if not self.validate_course(course_id):
                    if 'error_curso' not in context:
                        context['error_curso'] = [course_id]
                    else:
                        context['error_curso'].append(course_id)
                    logger.error("EdxLoginExternal - Course dont exists, user: {}, course_id: {}".format(user.id, course_id))
            if 'error_curso' not in context:
                for course_id in list_course:
                    if not self.validate_user(user, course_id):
                        if 'error_permission' not in context:
                            context['error_permission'] = [course_id]
                        else:
                            context['error_permission'].append(course_id)
                        logger.error("EdxLoginExternal - User dont have permission, user: {}, course_id: {}".format(user.id, course_id))
        if len(duplicate_courses) > 0:
            context['duplicate_courses'] = duplicate_courses
        # si el modo es incorrecto
        if not context['modo'] in [
                x[0] for x in EdxLoginUserCourseRegistration.MODE_CHOICES]:
            context['error_mode'] = ''
            logger.error("EdxLoginExternal - Wrong Mode, user: {}, mode: {}".format(user.id, context['modo']))
        return context
    
    def validarRutAllType(self, run):
        """
            Validate all Rut types
        """
        try:
            if run[0] == 'P':
                if 5 > len(run[1:]) or len(run[1:]) > 20:
                    logger.error("EdxLoginExternal - Rut Passport wrong, rut".format(run))
                    return False
            elif run[0:2] == 'CG':
                if len(run) != 10:
                    logger.error("EdxLoginExternal - Rut CG wrong, rut".format(run))
                    return False
            else:
                if not self.validarRut(run):
                    logger.error("EdxLoginExternal - Rut wrong, rut".format(run))
                    return False

        except Exception:
            logger.error("EdxLoginExternal - Rut wrong, rut".format(run))
            return False

        return True

    def enroll_create_user(self, course_ids, mode, lista_data, enroll):
        """
            Create and enroll the user with/without UChile account
            if email or rut exists not saved them
        """
        lista_saved = []
        lista_not_saved = []
        # guarda el form
        with transaction.atomic():
            for dato in lista_data:
                dato = [d.strip() for d in dato]
                dato[1] = dato[1].lower()
                if len(dato) == 3:
                    dato[2] = dato[2].upper()
                    dato[2] = dato[2].replace("-", "")
                    dato[2] = dato[2].replace(".", "")
                    dato[2] = dato[2].strip()
                if len(dato) == 2:
                    dato.append("")
                while len(dato[2]) > 0 and len(dato[2]) < 10 and 'P' != dato[2][0] and 'CG' != dato[2][0:2]:
                    dato[2] = "0" + dato[2]
                aux_email = dato[1]
                aux_pass = BaseUserManager().make_random_password(12)
                aux_pass = aux_pass.lower()
                aux_user = False
                if User.objects.filter(email=dato[1]).exists():
                    dato[1] = 'null'
                if dato[2] != "":
                    aux_rut = ''
                    if EdxLoginUser.objects.filter(run=dato[2]).exists():
                        aux_rut = dato[2]
                        edxlogin_user = EdxLoginUser.objects.get(run=dato[2])
                        if not edxlogin_user.have_sso:
                            aux_user = True
                    else:
                        edxlogin_user = self.create_user_with_run(dato, aux_pass)
                    if edxlogin_user is None:
                        lista_not_saved.append([aux_email, dato[2]])
                    else:
                        for course_id in course_ids:
                            self.enroll_course(edxlogin_user, course_id, enroll, mode)
                        lista_saved.append({
                            'email_o': aux_email,
                            'email_d': edxlogin_user.user.email,
                            'nombreCompleto': edxlogin_user.user.profile.name.strip(),
                            'rut': dato[2],
                            'rut_aux': aux_rut,
                            'password': aux_pass,
                            'sso': edxlogin_user.have_sso,
                            'exists': aux_user
                        })
                else:
                    if dato[1] != 'null':
                        user_data = {
                            'email':dato[1],
                            'nombreCompleto':dato[0],
                            'pass': aux_pass
                        }
                        user = self.create_user_by_data(user_data)
                    else:
                        aux_user = True
                        user = User.objects.get(email=aux_email)
                    for course_id in course_ids:
                        self.enroll_course_user(user, course_id, enroll, mode)
                    lista_saved.append({
                        'email_o': aux_email,
                        'email_d': user.email,
                        'nombreCompleto': user.profile.name.strip(),
                        'rut': '',
                        'rut_aux': '',
                        'password': aux_pass,
                        'sso': False,
                        'exists': aux_user
                    })
        return lista_saved, lista_not_saved

    def create_user_with_run(self, dato, aux_pass):
        """
            Get user data and create the user
        """

        try:
            username = self.get_username(dato[2])
            user_data = self.get_user_data(username)
            user_data['username'] = username
            user_data['pass'] = aux_pass
            edxlogin_user = self.create_user_external(user_data, dato)
            return edxlogin_user
        except Exception:
            with transaction.atomic():
                if dato[1] == 'null':
                    return None
                user_data = {
                    'email': dato[1],
                    'nombreCompleto':dato[0],
                    'pass': aux_pass
                }
                user = self.create_user_by_data(user_data)
                edxlogin_user = EdxLoginUser.objects.create(
                    user=user,
                    have_sso=False,
                    run=dato[2]
                )
            return edxlogin_user

    def create_user_external(self, user_data, dato):
        """
            Create the user given the user data.
            If the email exists, get new email address.
        """
        with transaction.atomic():
            user_data['email'] = dato[1] if dato[1] != 'null' else self.get_user_email(user_data['rut'])
            if user_data['email'] == 'null':
                return None
            user = self.create_user_by_data(user_data)
            edxlogin_user = EdxLoginUser.objects.create(
                user=user,
                have_sso=True,
                run=user_data['rut']
            )
        return edxlogin_user
    
    def enroll_course_user(self, user, course, enroll, mode):
        """
            Enroll the user in the course.
        """
        from common.djangoapps.student.models import CourseEnrollment, CourseEnrollmentAllowed

        if enroll:
            CourseEnrollment.enroll(
                user,
                CourseKey.from_string(course),
                mode=mode)
        else:
            CourseEnrollmentAllowed.objects.create(
                course_id=CourseKey.from_string(course),
                email=user.email,
                user=user)
