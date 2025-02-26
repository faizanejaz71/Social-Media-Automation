from django.urls import path
from . import views



urlpatterns = [
    path('', views.adminLogin, name='login'),
    path('home/', views.home, name='home'),
    path('csv/', views.csv, name='csv'),
    path('card/', views.card, name='card'),
    path('account_details/', views.account_details, name='account_details'),
    path('account_list/', views.account_list, name='account_list'),
    path('upload-csv/', views.upload_csv, name='upload_csv'),


    path('process-accounts/', views.process_accounts, name='process_accounts'),
    path('twitter/callback/', views.twitter_callback, name='twitter_callback'),


    path('action/', views.action, name='action'),

    path('follow/', views.follow_view, name="follow"),
    path('unfollow/', views.unfollow_view, name="unfollow"),
    path('tweet/', views.tweet, name="tweet"),
    path('retweet/', views.retweet_with_thoughts, name="retweet-thoughts"),
    path('like/', views.like_tweet, name="like"),
    path("comment-on-tweet/", views.comment_on_tweet, name="comment_on_tweet"),


]