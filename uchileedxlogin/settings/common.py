def plugin_settings(settings):    
    edxlogin_host = 'http://172.25.14.37'

    settings.EDXLOGIN_CLIENT_ID = 'desa'
    settings.EDXLOGIN_CLIENT_SECRET = 'desa'
    settings.EDXLOGIN_RESULT_VALIDATE = edxlogin_host + ':9513/validate'
    settings.EDXLOGIN_USER_INFO_URL = edxlogin_host + ':8181/cxf/por-atributos-usuario/usuario'
    settings.EDXLOGIN_USER_EMAIL = edxlogin_host + ':7913/obtenerEstadoCuentaPasaporte'
    settings.EDXLOGIN_REQUEST_URL = edxlogin_host + ':9513/login'    
    
