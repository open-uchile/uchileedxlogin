def plugin_settings(settings):
    edxlogin_host = 'http://172.25.14.193'

    settings.EDXLOGIN_RESULT_VALIDATE = edxlogin_host + ':9513/validate'
    settings.EDXLOGIN_REQUEST_URL = edxlogin_host + ':9513/login'
    settings.EDXLOGIN_KEY = ''
    settings.EDXLOGIN_USER_INFO_URL = ''
