from django.shortcuts import render
import os
from ApiPlatform.api_handler import APIResponse


class ServerMaintenanceMiddleware:
    """
    Middleware to display "App Under Maintenance" message if the server is down.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Check if the system is under maintenance
        if os.environ.get("MAINTENANCE_MODE", "off") == "on":
            # Check if the request is for the admin or API; you can exclude specific URLs if needed
            if request.path.startswith("/admin") or request.path.startswith("/api"):
                return APIResponse.HTTP_503_SERVICE_UNAVAILABLE(message="App Under Maintenance")

            # For other pages, render a maintenance HTML page
            return render(request, "503.html")

        # Proceed with the request if not in maintenance mode
        response = self.get_response(request)
        return response
