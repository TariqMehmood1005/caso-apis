from rest_framework.test import APITestCase, APIClient
from django.contrib.auth import get_user_model


class UserLevelValidationTest(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.User = get_user_model()

        # Create a user with 'Agent' level
        self.agent_user = self.User.objects.create_user(
            username='agent_user',
            email='agent@example.com',
            password='password123',
            user_level='Agent'
        )

        # Create a user with 'Admin' level
        self.admin_user = self.User.objects.create_user(
            username='admin_user',
            email='admin@example.com',
            password='password123',
            user_level='Admin'
        )

        # Create a user with 'Player' level
        self.player_user = self.User.objects.create_user(
            username='player_user',
            email='player@example.com',
            password='password123',
            user_level='Player'
        )

    def test_agent_user_access(self):
        """Test that an Agent user has access."""
        self.client.login(username='agent_user', password='password123')
        response = self.client.post('/api/create_player/')  # Update URL as needed
        self.assertEqual(response.status_code, 201)

    def test_admin_user_access(self):
        """Test that an Admin user has access."""
        self.client.login(username='admin_user', password='password123')
        response = self.client.post('/api/create_player/')  # Update URL as needed
        self.assertEqual(response.status_code, 201)

    def test_player_user_access(self):
        """Test that a Player user is forbidden."""
        self.client.login(username='player_user', password='password123')
        response = self.client.post('/api/create_player/')  # Update URL as needed
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.data['message'],
            'You are not authorized to access this resource.'
        )

    def test_unauthenticated_user_access(self):
        """Test that an unauthenticated user is unauthorized."""
        response = self.client.post('/api/create_player/')  # Update URL as needed
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data['message'], 'User is not authenticated.')
