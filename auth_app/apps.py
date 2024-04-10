'''Function printing python version.'''
from django.apps import AppConfig


class AuthAppConfig(AppConfig):
    '''Function printing python version.'''
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'auth_app'

    def ready(self):
            import auth_app.signals