# myapp/views.py
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.renderers import JSONRenderer
from rest_framework import status
from smtplib import SMTPException
from django.shortcuts import redirect
from django.contrib.auth.hashers import make_password
from rest_framework.decorators import renderer_classes
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from django.template.loader import render_to_string
import requests
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .models import EmailVerification
from .serializers import CustomUserSerializer  # Import your custom serializer
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes,force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.conf import settings
from rest_framework import status
from rest_framework_simplejwt.views import TokenObtainPairView
import environ
env = environ.Env()
environ.Env.read_env()
User = get_user_model()



@api_view(['POST'])
def signup(request):
    try:
        # print(a)
        if "email" in request.data and User.objects.filter(email=request.data["email"]).exists():
            return Response({"registration":"user already exist"},409)
        
        if len(request.data["password"])<6:
            return Response({"password":"password should be higher than 6 character"},400)
        

        serializer = CustomUserSerializer(data=request.data) 
        if serializer.is_valid():
            serializer.save()
            user = User.objects.get(email=request.data['email'])
            # Create an email verification entry
            verification = EmailVerification.objects.create(user=user)

            # Send verification email
            current_site = get_current_site(request)
            verification_url = reverse('verify-email', kwargs={'token': str(verification.token)})
            verification_url = f'http://{current_site.domain}{verification_url}'
            html_content = render_to_string('verifymail.html', {'verification_url': verification_url,'name':user.first_name})
            send_mail(
                    'Verify Your Email',
                    f'Click the following link to verify your email: {verification_url}',
                    '"odunayo@Resume vantage" <from@example.com> ',
                    [user.email],
                    fail_silently=False,
                    html_message=html_content,
            )
            user.set_password(request.data['password'])
            user.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        if "email" in request.data and User.objects.filter(email=request.data["email"]).exists():
            user = User.objects.get(email=request.data['email'])
            user.delete()
        
        print(f'Something went wrong during registration {e}')
        return Response({'response':'something went wrong during registration'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
def verify_email(request, token):
    try:        
        verification = EmailVerification.objects.get(token=token)
        user = verification.user
        user.is_active = True
        user.save()
        verification.delete()
        return Response({'message': 'Email verified successfully.'})
    except EmailVerification.DoesNotExist:
        return Response({'token': 'verification token invalid or expired.'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def test_token(request):
    user = request.user
    serializer = CustomUserSerializer(user)  # Use CustomUserSerializer

    user = User.objects.get(email=user)
    return Response(serializer.data)

GOOGLE_AUTHORIZATION_URL = 'https://accounts.google.com/o/oauth2/auth'
GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token'
GOOGLE_CLIENT_ID = '49556748540-rf9ne1n9csi6g7c5hj6lc4ejfeu9d45b.apps.googleusercontent.com'  # Replace with your actual client ID
GOOGLE_CLIENT_SECRET = env('GOOGLE_CLIENT_SECRET')  # Replace with your actual client secret
GOOGLE_REDIRECT_URI = 'http://localhost:8000/auth/google/redirected'  # Replace with your actual redirect URI
import secrets
@csrf_exempt
@api_view(('GET',))
@renderer_classes((JSONRenderer,))
def google_auth_initiate(request):
    # Generate a unique state value and store it in the session
    # del request.session['google_auth_state']
    

    state = secrets.token_urlsafe(16)
    request.session['google_auth_state2'] = state
    # Build the authorization URL
    auth_url = f'{GOOGLE_AUTHORIZATION_URL}?client_id={GOOGLE_CLIENT_ID}&redirect_uri={GOOGLE_REDIRECT_URI}&response_type=code&scope=email%20profile&state={state}'
    print("views stage")
    return Response(auth_url)

@csrf_exempt
@api_view(('GET',))
@renderer_classes((JSONRenderer,))
def google_auth_callback(request):
    
    # Get the authorization code and state from the request data
    code = request.GET.get('code')
    state = request.GET.get('state')
    # Verify that code and state are present
    if not code or not state:
        return Response({'parameters':'Missing code or state parameters'},403)

    # Verify that the state matches the one stored in the session
    stored_state = request.session.get('google_auth_state2')
    
    if state != stored_state:
        return Response({'state':'State mismatch, make sure request is initiated and completed with the same client and that the server has sucesfully set the sessionId cookie on the client'},403)

    # Clear the state from the session to prevent replay attacks
    del request.session['google_auth_state2']
    # Exchange the code for tokens
    token_data = {
        'code': code,
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': env('GOOGLE_CLIENT_SECRET'),
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'grant_type': 'authorization_code'
    }

    response = requests.post(GOOGLE_TOKEN_URL, data=token_data)

    if response.status_code == 200:
        tokens = response.json()
        access_token = tokens.get('access_token')

        # Use the access token to get user information from Google
        user_info_response = requests.get('https://www.googleapis.com/oauth2/v1/userinfo', headers={'Authorization': f'Bearer {access_token}'})

        if user_info_response.status_code == 200:
            user_info = user_info_response.json()
            user_email = user_info.get('email')
            # print(user_info)

            user, created = User.objects.get_or_create(email=user_email, defaults={'email': user_email})
            if created:
                # generatePassword = secrets.token_urlsafe(12)
                # Set a dummy password for the user
                # user.set_password(generatePassword)
                user.is_active=True
                user.is_google=True
                user.first_name=user_info.get('given_name')
                user.last_name=user_info.get('family_name')
                user.save()
            # Assuming you have a profile model associated with the user
            # You can create a profile for the user if not already created
            # profile, created = UserProfile.objects.get_or_create(user=user)
            generatePassword = secrets.token_urlsafe(12)
                # Set a dummy password for the user
            user.set_password(generatePassword)
            user.save()
            # Generate tokens for the user (use Django Rest Framework JWT or SimpleJWT)
            tokens_serializer = TokenObtainPairSerializer(data={'email': user_email, 'password': generatePassword})
            tokens_serializer.is_valid(raise_exception=True)
            tokens = tokens_serializer.validated_data

            # You can return the tokens in the response
            # return Response({'access': tokens['access'], 'refresh': tokens['refresh']})
            redirect_url = f'http://example.com/redirect?access={tokens["access"]}&refresh={tokens["refresh"]}'

            # Redirect the user to the client-side URL
            return redirect(redirect_url)
            # return Response({'email': user_email})
        else:
            return Response({'process': 'Failed to retrieve user information from Google'}, status=user_info_response.status_code)
    else:
        return Response({'exchange': 'Failed to exchange code for tokens'}, status=response.status_code)


from rest_framework_simplejwt.tokens import RefreshToken
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def refresh_token(request):
    refresh = RefreshToken(request.data.get('refresh'))
    access_token = str(refresh.access_token)
    # Return the new access token in the response
    return Response({'access': access_token})



@api_view(['POST'])
def reset_password(request):
    email = request.data.get('email')
    if not email:
        return Response({"details":"email not supplied"},400)
    if not User.objects.filter(email=email).exists():
        return Response({"credentials":"email not registered"},404)
    user = User.objects.get(email=email)
    if user.is_google is True:
        return Response({"credentials":"you registered with Google"},404)
    otp = secrets.token_urlsafe(20)
    user.otp=otp

    user.can_reset_password=True
    user.save()
    current_site = get_current_site(request)
    # verification_url = reverse('reset-password-confirm', kwargs={'token': otp})
    verification_url = f'/auth/reset-password-confirm/?token={otp}'
    verification_url = f'http://{current_site.domain}{verification_url}'
    html_content = render_to_string('resetpassword_mail.html', {'verification_url': verification_url,'name':user.first_name})

    send_mail(
        'Reset your password',
        f'Click the following link to reset your password: {verification_url}',
        '"odunayo@Resume vantage" <from@example.com> ',
        [user.email],
        fail_silently=False,
        html_message=html_content,
    )
    # Return the new access token in the response
    return Response({'access': "okay"})



@api_view(['GET'])
def reset_password_confirm(request):
    token = request.GET.get('token', 'default_value')
    if not User.objects.filter(otp=token).exists():
        return Response({"credentials":"token not found"},404)

    user = User.objects.get(otp=token).email
    return redirect(f'http://127.0.0.1:5501/update_password.html?email={user}')

@api_view(['POST'])
def update_password(request):
    password = request.data.get('password')
    email = request.data.get('email')
    if not password:
        return Response ({'field':'password cannot be empty'},400)
    if not email:
        return Response ({'field':'email cannot be empty'},400)
    print(len(password))
    if len(password)<6:
        return Response({"password":"password should be higher than 6 characters"},400)
    if not User.objects.filter(email=email).exists():
        return Response({"credentials":"user not found"},404)
    user = User.objects.get(email=email)

    if not user.can_reset_password:
        return Response({"permission":"this token has expired"},403)
    user.set_password(password)
    user.can_reset_password=False
    user.save()


    return Response({'message':'passsword updated'})
