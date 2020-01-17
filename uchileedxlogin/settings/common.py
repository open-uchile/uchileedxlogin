def plugin_settings(settings):
    settings.EDXLOGIN_CLIENT_ID = '1234'
    settings.EDXLOGIN_CLIENT_SECRET = '5678'
    settings.EDXLOGIN_SCOPE = 'openid run name email'
    settings.EDXLOGIN_HOST = 'http://172.25.14.246'
    settings.EDXLOGIN_RESULT_VALIDATE = settings.EDXLOGIN_HOST + ':9513/validate'
    settings.EDXLOGIN_USER_INFO_URL = settings.EDXLOGIN_HOST + ':8181/cxf/por-atributos-usuario/usuario'
    settings.EDXLOGIN_USER_EMAIL = settings.EDXLOGIN_HOST + ':7913/obtenerEstadoCuentaPasaporte'
    settings.EDXLOGIN_REQUEST_URL = settings.EDXLOGIN_HOST + ':9513/login'
    settings.EDXLOGIN_SERVICE = 'http://claveunica.dgd.uchile.cl/uchileedxlogin/callback'
    
