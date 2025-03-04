# views.py
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from .models import User, Message, MessageConversation
from .serializers import UserSerializer, MessageSerializer, MessageConversationSerializer
from .api_handler import APIResponse


class MessageViewSet(viewsets.ModelViewSet):
    queryset = Message.objects.all()
    serializer_class = MessageSerializer
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        sender = request.user
        receiver_id = request.data.get('receiver_id')
        message_content = request.data.get('message_content')
        message_type = request.data.get('message_type')

        try:
            receiver = User.objects.get(id=receiver_id)
        except User.DoesNotExist:
            return APIResponse.HTTP_404_NOT_FOUND(message="Receiver not found")

        message = Message.objects.create(
            sender=sender,
            receiver=receiver,
            message_content=message_content,
            message_type=message_type,
            status='pending'
        )
        return APIResponse.HTTP_201_CREATED(data=MessageSerializer(message).data)


class MessageConversationViewSet(viewsets.ModelViewSet):
    queryset = MessageConversation.objects.all()
    serializer_class = MessageConversationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return MessageConversation.objects.filter(user=user)


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
