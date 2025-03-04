from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import User as DjangoUser


def check_user_password(user_id, user_provided_password):
    """
    Compare the provided password with the stored hashed password.
    """

    # Retrieve the DjangoUser object based on the user ID
    try:
        django_user = DjangoUser.objects.get(id=user_id)
    except DjangoUser.DoesNotExist:
        return "User not found."

    # Check if the provided password matches the stored hashed password
    if check_password(user_provided_password, django_user.password):
        return "Password is correct."

    return "Password is incorrect."
