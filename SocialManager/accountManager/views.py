from django.shortcuts import render
import tweepy
from django.conf import settings
from django.shortcuts import redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login


# Create your views here.



from django.http import HttpResponse

#user camel case funtion names 

def home(request):
    return render(request, 'index.html')

def adminLogin(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        if not User.objects.filter(username=username).exists():
            messages.error(request, 'Invalid Username')
            return redirect('login')

        user = authenticate(username=username, password=password)

        if user is None:
            messages.error(request, 'Invalid Password')
            return redirect('login')
        else:
            login(request, user) 

            if user.is_superuser:  
                return redirect('home')
            else: 
                return redirect('login') 

    return render(request, 'login.html')




def twitter_login(request):
    auth = tweepy.OAuth2UserHandler(
        client_id=settings.TWITTER_API_KEY,
        redirect_uri='http://127.0.0.1:8000/twitter/callback/',
        scope=["tweet.read", "users.read"]
    )
    redirect_url = auth.get_authorization_url()
    return redirect(redirect_url)

def twitter_callback(request):
    auth = tweepy.OAuth2UserHandler(
        client_id=settings.TWITTER_API_KEY,
        redirect_uri='http://127.0.0.1:8000/twitter/callback/',
        scope=["tweet.read", "users.read"]
    )
    access_token = auth.fetch_token(request.GET.get('code'))
    api = tweepy.Client(access_token['access_token'])
    user = api.get_me()
    context = {'user': user}
    return render(request, 'twitter_success.html', context)




