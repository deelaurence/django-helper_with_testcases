# myapp/serializers.py
from rest_framework import serializers
from .models import CustomUser

class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 
                  'email',  
                  'first_name', 
                  'last_name', 
                  'is_active', 
                  'is_staff', 
                  'picture', 
                  'last_seen']

    # Optionally, you can add extra validation or customization for specific fields
    # For example, you might want to ensure that the email field is read-only
    extra_kwargs = {
        'email': {'read_only': True},
    }


class GoogleLoginSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True)

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()