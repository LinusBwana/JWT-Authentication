from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated

from django.contrib.auth.models import User
from .serializers import UserSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from .serializers import LoginSerializer
from rest_framework import status
from .permissions import IsActiveUser, IsAdminUser
from .auth import CustomJWTAuthentication

# Create your views here.
@api_view(['GET'])
@permission_classes([IsActiveUser])
@authentication_classes([CustomJWTAuthentication])
def Home(request):
    return Response("Hello world. This is for everyone")


@api_view(['GET'])
@permission_classes([IsAdminUser])
@authentication_classes([CustomJWTAuthentication])
def MyProtectedRoute(request):
    return Response("You have been permitted to access the protected route. For admins only")
 

@api_view(['POST'])
def login_user(request):
    serializer = LoginSerializer(data=request.data)
    
    if serializer.is_valid():
        user = serializer.validated_data['user']
        user_data = UserSerializer(user).data
        return Response({
            'refresh': serializer.validated_data['refresh'],
            'access': serializer.validated_data['access'],
            'user': user_data
        }, status=status.HTTP_200_OK)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




class MyTokenObtainPairView(TokenObtainPairView):

    """"
    `MyTokenObtainPairView` extends SimpleJWT's 
    `TokenObtainPairView` to handle standard username/password authentication, 
    token generation, and customizes the `post()` method 
    to include additional user data in the token response.
    """
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