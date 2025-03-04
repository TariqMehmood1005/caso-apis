# middlewares.py
from django.shortcuts import redirect
from django.conf import settings
from django.urls import reverse
import zoneinfo
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin

class SitePublishedMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Add logic to check if the site is published
        # Assume we have a `settings.SITE_PUBLISHED` flag or fetch this from the database
        site_published = getattr(settings, 'SITE_PUBLISHED', False)

        # Exclude the waitlist and admin pages from the redirect
        if not site_published and not request.path.startswith(
                ('/admin', reverse('ApiPlatform:waitlist'), reverse('ApiPlatform:join_waitlist'))):
            return redirect('ApiPlatform:waitlist')

        response = self.get_response(request)
        return response


class TimezoneMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        tzname = request.session.get("django_timezone")
        if tzname:
            timezone.activate(zoneinfo.ZoneInfo(tzname))
        else:
            timezone.deactivate()
        return self.get_response(request)


class DynamicHostMiddleware(MiddlewareMixin):
    def process_request(self, request):
        host = request.get_host()
        protocol = "https" if request.is_secure() else "http"
        base_url = f"{protocol}://{host}"
        
        settings.HOST = base_url
        settings.BASE_API_URL = f"{base_url}/api/v1"
        
        print(f"settings.HOST: {settings.HOST}")
        print(f"settings.BASE_API_URL: {settings.BASE_API_URL}")
        
        
