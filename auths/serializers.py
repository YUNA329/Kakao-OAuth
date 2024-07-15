from rest_framework import serializers
from auths.models import MutsaUser

class MutsaUserResponseSerializer(serializers.ModelSerializer):
    model = MutsaUser
    fields = ['id', 'nickname', 'description']
    extra_kwargs = {
        field: {'read_only':True} for field in fields
    }
    
class KakaoLoginRequestSerilalizer(serializers.Serializer):
    access_code = serializers.CharField()
    
class KakaoRegisterRequestSerializer(serializers.Serializer):
    access_code = serializers.CharField()
    description = serializers.CharField()