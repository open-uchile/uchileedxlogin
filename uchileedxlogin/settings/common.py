def plugin_settings(settings):
    settings.EDXLOGIN_CLIENT_ID = '1234'
    settings.EDXLOGIN_CLIENT_SECRET = '5678'
    settings.EDXLOGIN_SCOPE = 'openid run name email'
    settings.HOST = 'http://172.25.14.246'
    settings.RESULT_VALIDATE = settings.HOST + ':9513/validate'
    settings.USER_INFO_URL = settings.HOST + ':8181/cxf/por-atributos-usuario/usuario'
    settings.USER_EMAIL = settings.HOST + ':7913/obtenerEstadoCuentaPasaporte'
    settings.REQUEST_URL = settings.HOST + ':9513/login'
    settings.SERVICE = 'http://claveunica.dgd.uchile.cl/uchileedxlogin/callback'
    
