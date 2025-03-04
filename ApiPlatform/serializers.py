from rest_framework import serializers
from .models import AgentChat, Payment


class AgentChatSerializer(serializers.ModelSerializer):
    class Meta:
        model = AgentChat
        fields = '__all__'  # Include all fields of AgentChat model

    def to_dict(self, instance):
        data = super().to_dict(instance)
        data['agent'] = instance.agent_id.username if instance.agent_id else None
        return data



## update code
class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = '__all__'