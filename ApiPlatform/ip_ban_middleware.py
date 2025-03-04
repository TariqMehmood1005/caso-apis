from datetime import timedelta, datetime
from django.core.cache import cache
from django.shortcuts import render
from .models import BannedIP
from django.utils.timezone import now


class BanIPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.request_limit = 1000  # Max requests
        self.time_window = 60  # Time window in seconds (1 minute)
        self.unblock_after_time = 30  # Unban after 30 minutes

    def __call__(self, request):
        # Skip blocking for admin requests
        if request.path.startswith('/admin/'):
            return self.get_response(request)

        # Handle IP blocking logic
        blocking_res = self.handle_blocking(request)
        if blocking_res:
            return blocking_res

        response = self.get_response(request)
        return response

    def handle_blocking(self, request):
        ip = self.get_client_ip(request)

        # Check if the IP is banned
        try:
            banned_ip = BannedIP.objects.get(ip_address=ip)

            if banned_ip.is_active():
                # If the IP is banned, block access
                return self.blocked_response(request)
            else:
                # Remove expired ban
                banned_ip.delete()

        except BannedIP.DoesNotExist:
            pass  # The IP is not banned, continue processing

        # Track request attempts
        self.track_ip_requests(ip)

        return None

    def track_ip_requests(self, ip):
        # Get the current time
        current_time = now()

        # Fetch the list of timestamps for the IP from cache
        ip_requests = cache.get(ip, [])

        # Remove timestamps that are outside the time window
        ip_requests = [t for t in ip_requests if current_time - t < timedelta(seconds=self.time_window)]

        # Add the current timestamp to the list
        ip_requests.append(current_time)

        # Update the cache with the new request times
        cache.set(ip, ip_requests, timeout=self.time_window)

        # If the number of requests exceeds the limit, block the IP
        if len(ip_requests) > self.request_limit:
            # Ban the IP address and store the ban in the database
            self.ban_ip(ip, self.unblock_after_time)

            # Return a response indicating the user is blocked
            return self.blocked_response()

    @staticmethod
    def ban_ip(ip, unblock_after_time):
        # Set the ban duration to 10 seconds
        ban_expiry = now() + timedelta(minutes=unblock_after_time)  # Ban for

        # Create a new BannedIP object and ensure created_at is set
        BannedIP.objects.create(
            ip_address=ip,
            ban_expiry=ban_expiry,
            created_at=datetime.now(),  # Ensure created_at is set to the current time
        )

        # Store unblock time in cache (for quick lookup)
        cache.set(f"unblock_{ip}", now() + timedelta(seconds=10), timeout=10)

    @staticmethod
    def blocked_response(request=None):
        # Render a custom HTML page when the IP is blocked
        return render(request, 'blocked_ip.html') if request else render(request, 'blocked_ip.html')

    @staticmethod
    def get_client_ip(request):
        # Get the real client IP
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
