from django.apps import AppConfig


class ApiPlatformConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'ApiPlatform'

    def ready(self):
        import ApiPlatform.signals