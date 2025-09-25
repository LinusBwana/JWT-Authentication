from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated

from django.contrib.auth.models import User
from .serializers import UserSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken

# Create your views here.
@api_view(['GET'])
def Home(request):
    return Response("Hello world")


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def MyProtectedRoute(request):
    return Response("You have been permitted to access the protected route")


class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = TokenObtainPairSerializer

    def post(self, request, *args, **kwargs):

        # Proceed with the parent method to handle token generation
        try:
            response = super().post(request, *args, **kwargs)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        # get username from form submission
        username = request.POST.get('username')
        if username:
            # Add user details to the response
            try:
                user = User.objects.get(username=username)
                user_serializer = UserSerializer(user)
                response.data['user'] = user_serializer.data
            except User.DoesNotExist:
                pass
                
        return response