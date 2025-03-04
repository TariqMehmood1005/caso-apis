from django.core.mail import EmailMessage
from django.conf import settings
from django.http import HttpResponse


class EmailConfig:
    def __init__(self, recipient_email: str, response_data: dict, user_created: bool = False):
        self.recipient_email = recipient_email
        self.admin_email = settings.ADMIN_DEFAULT_FROM_EMAIL
        self.response_data = response_data
        self.user_created = user_created
        self.subjects = {
            "waitlist": "Welcome to the Coins Selling Platform Waitlist",
            "user_creation": "Welcome to the Coins Selling Platform"
        }

        self.user_messages = {
            "waitlist": (
                f"Dear {response_data['email']},\n\n"
                f"Thank you for joining the waitlist for our 'Coins Selling Platform'.\n\n"
                f"Here are your login details:\n"
                f"Username: {response_data['email']}\n"
                f"Password: {response_data['password']}\n\n"
                "Please keep this information secure.\n\n"
                "Best regards,\n"
                "The Dark Bytes Team"
            ),
            "user_creation": (
                f"Dear {response_data['email']},\n\n"
                "Welcome to the Coins Selling Platform!\n\n"
                "You can log in with the details provided. Please reach out to support if you have any issues.\n\n"
                "Best regards,\n"
                "The Dark Bytes Team"
            )
        }
        self.admin_message = (
            f"Admin Notification:\n\n"
            f"A new user has joined.\n\n"
            f"User Email: {response_data['email']}\n"
            f"Username: {response_data['email']}\n\n"
            "Please follow up as needed."
        )

    def send_email(self, email_type="waitlist"):
        # Only send emails if the user was created successfully
        if not self.user_created:
            return HttpResponse("User creation unsuccessful, emails not sent.")

        try:
            # Set the subject and message based on email_type
            subject = self.subjects.get(email_type, "User Notification")
            user_message = self.user_messages.get(email_type, "Welcome to our platform!")

            # Create and send email to the user
            user_email = EmailMessage(
                subject,
                user_message,
                settings.DEFAULT_FROM_EMAIL,
                [self.recipient_email]
            )
            user_email.extra_headers = {
                'X-Mailer': 'Django',
                'Message-ID': f"<{email_type}-{self.recipient_email}@{settings.DEFAULT_FROM_EMAIL.split('@')[1]}>"
            }
            user_email.send(fail_silently=False)

            # Create and send email to the admin
            admin_email = EmailMessage(
                f"New Registration - {self.response_data['email']}",
                self.admin_message,
                settings.DEFAULT_FROM_EMAIL,
                [self.admin_email]
            )
            admin_email.extra_headers = {
                'X-Mailer': 'Django',
                'Message-ID': f"<admin-{self.recipient_email}@{settings.ADMIN_DEFAULT_FROM_EMAIL.split('@')[1]}>"
            }
            admin_email.send(fail_silently=False)

            print(f"Emails sent to {self.recipient_email} and admin successfully.")
            return HttpResponse("Emails sent to user and admin successfully!")

        except Exception as e:
            print(f"Failed to send email: {str(e)}")
            return HttpResponse(f"Failed to send email: {str(e)}")
