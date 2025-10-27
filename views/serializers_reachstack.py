from rest_framework import serializers

class RegisterSerializer(serializers.Serializer):
    email = serializers.CharField()
    password = serializers.CharField()
    username =  serializers.CharField()  
    org_name = serializers.CharField() 
       

class RegisterResponseSerializer(serializers.Serializer):
    org_id = serializers.CharField()