from rest_framework.permissions import BasePermission
from .models import User
from rest_framework.exceptions import PermissionDenied


class IsAdmin(BasePermission):
    """
    Custom permission class to check if the user is an 'Agent' or 'Admin'
    based on the role of the user.
    """

    def has_permission(self, request, view):
        ## just for testing to get userid ids

        users = User.objects.all()
        for user in users:
            print("getting user ids....")
            print(user.id)
            print(user.role_id.roles)
        ###

        # Check if the user is authenticated
        if not request.user or not request.user.is_authenticated:
            raise PermissionDenied("User is not authenticated.")

        # Get the 'player_created_by' from the request data
        player_created_by_uuid = request.data.get('player_created_by')
        print(f'player_created_by_uuid is {player_created_by_uuid}')
        if not player_created_by_uuid:
            raise PermissionDenied("Player creation requires the 'player_created_by' field.")

        try:
            # Get the User object corresponding to the 'player_created_by' UUID
            admin_role = User.objects.get(id=player_created_by_uuid)
        except User.DoesNotExist:
            raise PermissionDenied(f"Admin with UUID {player_created_by_uuid} does not exist.")

        # Check if the 'player_created_by' user is an Agent or Admin
        # if admin_user.role_id.roles in [ 'Admin']:
        print(admin_role.role_id.roles)
        if admin_role.role_id.roles == 'Admin':
            print('admin created the player')
            return True  # Grant permission to create player
        else:
            raise PermissionDenied(
                "You are not authorized to create a player as the specified agent is not an Agent or Admin.")

        # # If the user is not an Admin, deny player creation
        # return APIResponse.HTTP_403_FORBIDDEN(
        #     message="Only Admins are authorized to create players."
        # )
