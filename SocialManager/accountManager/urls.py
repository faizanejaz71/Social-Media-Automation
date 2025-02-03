from django.urls import path
from . import views



urlpatterns = [
    path('home/', views.home, name='home'),
    path('', views.adminLogin, name='login'),
    path('twitter/login/', views.twitter_login, name='twitter-login'),
    path('twitter/callback/', views.twitter_callback, name='twitter-callback'),

]