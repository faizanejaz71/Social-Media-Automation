from django.shortcuts import render
# import tweepy
from django.conf import settings
from django.shortcuts import redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login
import pandas as pd
from .models import TwitterAccount
from django.utils import timezone
import secrets
import hashlib
import base64
from .utils import get_oauth_session
import requests
import time


def home(request):
    twitter = TwitterAccount.objects.filter(account_type = "twitter").count()
    facebook = TwitterAccount.objects.filter(account_type="facebook").count()
    tiktok = TwitterAccount.objects.filter(account_type="tiktok").count()
    instagram = TwitterAccount.objects.filter(account_type="instagram").count()
    context ={
        'twitter_accounts' : twitter,
        'facebook_accounts': facebook,
        'tiktok_accounts'  : tiktok,
        'instagram_accounts'  : instagram,
        }
    return render(request, 'Sneat/index.html', context)

def csv(request):
    return render(request, 'Sneat/upload-csv.html')

# card
def card(request):
    return render(request, 'Sneat/cards.html')
def action(request):
    return render(request, 'Sneat/actions.html')

# account_details
def account_details(request):
    return render(request, 'Sneat/account_detail.html')

#account list
def account_list(request):
    accounts = TwitterAccount.objects.all()
    context ={
        'accounts' : accounts,
        }
    return render(request, 'Sneat/account-list.html', context)

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

    return render(request, 'Sneat/auth-login-basic.html')

TWITTER_AUTH_URL = "https://twitter.com/i/oauth2/authorize"
TWITTER_TOKEN_URL = "https://api.twitter.com/2/oauth2/token"

def upload_csv(request):
    """Upload CSV and store account list in session"""
    if request.method == 'POST' and request.FILES.get('csv_file'):
        csv_file = request.FILES['csv_file']
        df = pd.read_csv(csv_file)
        accounts = df.to_dict('records')
        request.session['accounts_to_process'] = accounts
        request.session['current_account_index'] = 0
        return redirect('process_accounts')
    return render(request, 'Sneat/upload-csv.html')

def generate_pkce():
    """Generate PKCE code_verifier and code_challenge"""
    code_verifier = secrets.token_urlsafe(64)[:128]  # 43-128 chars
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b'=').decode('utf-8')
    return code_verifier, code_challenge

def process_accounts(request):
    """Initiate Twitter OAuth with PKCE"""
    accounts = request.session.get('accounts_to_process', [])
    current_index = request.session.get('current_account_index', 0)

    if current_index >= len(accounts):
        del request.session['accounts_to_process']
        del request.session['current_account_index']
        messages.success(request, 'All accounts have been processed!')
        return redirect('upload_csv')

    account = accounts[current_index]
    username = account.get('username')

    code_verifier, code_challenge = generate_pkce()
    request.session['oauth_code_verifier'] = code_verifier

    # Initialize OAuth session without code_challenge
    oauth = get_oauth_session()

    # Add PKCE to authorization URL
    authorization_url, state = oauth.authorization_url(
        TWITTER_AUTH_URL,
        code_challenge=code_challenge,
        code_challenge_method='S256'
    )

    request.session['oauth_state'] = state
    request.session['current_username'] = username
    request.session['current_account_index'] = current_index + 1

    time.sleep(5)

    return redirect(authorization_url)


def twitter_callback(request):
    """Handle Twitter OAuth Callback and Exchange Tokens"""
    code_verifier = request.session.get('oauth_code_verifier')
    authorization_code = request.GET.get('code')

    if not authorization_code:
        messages.error(request, "Authorization failed: Missing authorization code.")
        return redirect('upload_csv')

    client_id = settings.TWITTER_CLIENT_ID
    auth_header = base64.b64encode(f"{client_id}:".encode()).decode()

    try:
        # Step 1: Exchange Authorization Code for Access Token
        response = requests.post(
            settings.TWITTER_TOKEN_URL,
            headers={
                "Authorization": f"Basic {auth_header}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data={
                "grant_type": "authorization_code",
                "code": authorization_code,
                "redirect_uri": settings.TWITTER_REDIRECT_URI,
                "code_verifier": code_verifier,
                "client_id": client_id,
            },
        )

        if response.status_code != 200:
            raise Exception(f"Token exchange failed: {response.json()}")

        token = response.json()
        access_token = token.get('access_token')

        # Step 2: Fetch User Details (twitter_user_id)
        user_response = requests.get(
            "https://api.twitter.com/2/users/me",  # Twitter API endpoint
            headers={"Authorization": f"Bearer {access_token}"}
        )

        if user_response.status_code != 200:
            raise Exception(f"Failed to fetch user details: {user_response.json()}")

        user_data = user_response.json()
        twitter_user_id = user_data.get("data", {}).get("id")  # Extract Twitter User ID
        username = user_data.get("data", {}).get("username")

        if not twitter_user_id:
            raise Exception("Twitter User ID is missing in API response.")

        # Step 3: Save to Database
        TwitterAccount.objects.update_or_create(
            username=username,
            defaults={
                'access_token': access_token,
                'refresh_token': token.get('refresh_token'),
                'expires_at': timezone.now() + timezone.timedelta(seconds=token.get('expires_in')),
                'account_type': 'twitter',
                'twitter_user_id': twitter_user_id  # Save user ID
            }
        )

        messages.success(request, f'Successfully authorized @{username}!')
        return redirect('process_accounts')

    except Exception as e:
        messages.error(request, f'Authorization failed: {e}')
        return redirect('upload_csv')









# follow target account

def follow_target_account(request, target_username):
    user_lookup_url = f"https://api.twitter.com/2/users/by/username/{target_username}"
    headers = {"Authorization": f"Bearer {settings.TWITTER_BEARER_TOKEN}"}

    response = requests.get(user_lookup_url, headers=headers)

    if response.status_code != 200:
        print("Error: Target user not found")
        return {"error": "Target user not found"}

    target_user_id = response.json().get("data", {}).get("id")

    if not target_user_id:
        print("Error: Could not retrieve target user ID")
        return {"error": "Could not retrieve target user ID"}

    twitter_accounts = TwitterAccount.objects.all()

    for account in twitter_accounts:
        access_token = account.access_token

        user_info_url = "https://api.twitter.com/2/users/me"
        headers = {"Authorization": f"Bearer {access_token}"}

        user_info_response = requests.get(user_info_url, headers=headers)

        if user_info_response.status_code != 200:
            print(f"Error: Could not retrieve source user ID for {account.username}")
            continue

        source_user_id = user_info_response.json().get("data", {}).get("id")

        if not source_user_id:
            print(f"Error: No valid source user ID for {account.username}")
            continue

        follow_url = f"https://api.twitter.com/2/users/{source_user_id}/following"
        payload = {"target_user_id": target_user_id}

        max_retries = 3
        retries = 0

        while retries < max_retries:
            follow_response = requests.post(follow_url, json=payload, headers=headers)

            if follow_response.status_code == 200:
                print(f"Success: {account.username} followed {target_username}")
                break  # Exit retry loop on success

            elif follow_response.status_code == 429:
                wait_time = int(follow_response.headers.get("x-rate-limit-reset", 60))
                print(f"Rate limit hit. Waiting {wait_time} seconds before retrying...")
                time.sleep(wait_time)
                retries += 1
            else:
                print(f"Failed: {account.username} could not follow {target_username}, Status: {follow_response.status_code}")
                break

        # Wait 2 seconds before processing the next account to avoid rapid calls
        time.sleep(2)

    return {"success": "Follow action executed with retries and delays"}

def follow_view(request):
    if request.method == "POST":
        target_username = request.POST.get("target_username")

        if not target_username:
            messages.error(request, "Target username is required!")
            print("Error: No target username provided")
            return redirect("action")

        result = follow_target_account(request, target_username)

        if "error" in result:
            messages.error(request, result["error"])
            print(f"Follow action failed: {result['error']}")
        else:
            messages.success(request, "Follow action executed successfully!")
            print("Follow action executed successfully!")

        return redirect("action")

    return render(request, "Sneat/follow.html")






def unfollow_target_account(request, target_username):
    """Unfollow a target Twitter account using stored access tokens."""
    print(f"\n[DEBUG] Initiating unfollow process for: {target_username}")

    # Step 1: Get Target User ID
    user_lookup_url = f"https://api.twitter.com/2/users/by/username/{target_username}"
    headers = {"Authorization": f"Bearer {settings.TWITTER_BEARER_TOKEN}"}

    print(f"[DEBUG] Sending request to get user ID: {user_lookup_url}")
    response = requests.get(user_lookup_url, headers=headers)
    print(f"[DEBUG] Response Status: {response.status_code}, Response: {response.text}")

    if response.status_code != 200:
        print("[ERROR] Target user not found")
        return {"error": "Target user not found"}

    target_user_id = response.json().get("data", {}).get("id")
    print(f"[DEBUG] Retrieved Target User ID: {target_user_id}")

    if not target_user_id:
        print("[ERROR] Could not retrieve target user ID")
        return {"error": "Could not retrieve target user ID"}

    # Step 2: Fetch Stored Twitter Accounts
    twitter_accounts = TwitterAccount.objects.all()
    print(f"[DEBUG] Total Twitter Accounts Found: {len(twitter_accounts)}")

    for account in twitter_accounts:
        access_token = account.access_token
        print(f"\n[DEBUG] Processing Account: {account.username}")

        # Step 3: Get Source User ID (Authenticated User)
        user_info_url = "https://api.twitter.com/2/users/me"
        headers = {"Authorization": f"Bearer {access_token}"}

        print(f"[DEBUG] Fetching source user ID from: {user_info_url}")
        user_info_response = requests.get(user_info_url, headers=headers)
        print(f"[DEBUG] Response Status: {user_info_response.status_code}, Response: {user_info_response.text}")

        if user_info_response.status_code != 200:
            print(f"[ERROR] Could not retrieve source user ID for {account.username}")
            continue

        source_user_id = user_info_response.json().get("data", {}).get("id")
        print(f"[DEBUG] Retrieved Source User ID: {source_user_id}")

        if not source_user_id:
            print(f"[ERROR] No valid source user ID for {account.username}")
            continue

        # Step 4: Unfollow the Target User
        unfollow_url = f"https://api.twitter.com/2/users/{source_user_id}/following/{target_user_id}"
        print(f"[DEBUG] Attempting to unfollow {target_username} from {account.username}")

        max_retries = 3
        retries = 0

        while retries < max_retries:
            print(f"[DEBUG] Sending DELETE request to: {unfollow_url}")
            unfollow_response = requests.delete(unfollow_url, headers=headers)
            print(f"[DEBUG] Response Status: {unfollow_response.status_code}, Response: {unfollow_response.text}")

            if unfollow_response.status_code == 200:
                print(f"[SUCCESS] {account.username} successfully unfollowed {target_username}")
                break  # Exit retry loop on success

            elif unfollow_response.status_code == 429:
                wait_time = int(unfollow_response.headers.get("x-rate-limit-reset", 60))
                print(f"[RATE LIMIT] Rate limit hit. Waiting {wait_time} seconds before retrying...")
                time.sleep(wait_time)
                retries += 1
            else:
                print(f"[FAILED] {account.username} could not unfollow {target_username}, Status: {unfollow_response.status_code}")
                break

        # Step 5: Delay before processing the next account
        print("[DEBUG] Waiting 2 seconds before processing the next account...")
        time.sleep(2)

    print("[DEBUG] Unfollow action completed.")
    return {"success": "Unfollow action executed with retries and delays"}

def unfollow_view(request):
    if request.method == "POST":
        target_username = request.POST.get("target_username")
        print(f"[DEBUG] Received Unfollow Request for: {target_username}")

        if not target_username:
            messages.error(request, "Target username is required!")
            print("[ERROR] No target username provided")
            return redirect("unfollow")

        result = unfollow_target_account(request, target_username)

        if "error" in result:
            messages.error(request, result["error"])
            print(f"[ERROR] Unfollow action failed: {result['error']}")
        else:
            messages.success(request, "Unfollow action executed successfully!")
            print("[SUCCESS] Unfollow action executed successfully!")

        return redirect("unfollow")

    return render(request, "Sneat/actions.html")





def tweet(request):
    if request.method == "POST":
        tweet_text = request.POST.get("tweet_text")

        if not tweet_text:
            messages.error(request, "Tweet text is required!")
            return redirect("tweet_view")

        twitter_accounts = TwitterAccount.objects.all()

        for account in twitter_accounts:
            access_token = account.access_token
            post_tweet_url = "https://api.twitter.com/2/tweets"
            headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
            payload = {"text": tweet_text}

            max_retries = 3
            retries = 0

            while retries < max_retries:
                response = requests.post(post_tweet_url, json=payload, headers=headers)

                if response.status_code == 201:
                    print(f"Success: Tweet posted from {account.username}")
                    break

                elif response.status_code == 429:
                    wait_time = int(response.headers.get("x-rate-limit-reset", 60))
                    print(f"Rate limit hit. Waiting {wait_time} seconds before retrying...")
                    time.sleep(wait_time)
                    retries += 1
                else:
                    print(f"Failed: Could not post tweet from {account.username}, Status: {response.status_code}")
                    break

            # Wait 2 seconds before processing the next account
            time.sleep(2)

        messages.success(request, "Tweet posted successfully!")
        return redirect("tweet")

    return render(request, "Sneat/actions.html")





def retweet_with_thoughts(request):
    """Handles retweeting with a comment via Twitter API"""
    if request.method == "POST":
        tweet_id = request.POST.get("tweet_id")
        comment = request.POST.get("comment")

        if not tweet_id or not comment:
            messages.error(request, "Please enter both Tweet ID and your thoughts.")
            return redirect("retweet-thoughts")

        twitter_accounts = TwitterAccount.objects.all()

        for account in twitter_accounts:
            access_token = account.access_token
            retweet_url = "https://api.twitter.com/2/tweets"

            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            }
            payload = {
                "text": f"{comment} https://twitter.com/user/status/{tweet_id}"
            }

            response = requests.post(retweet_url, json=payload, headers=headers)

            if response.status_code == 201:
                messages.success(request, f"Successfully retweeted with thoughts using {account.username}")
            else:
                messages.error(request, f"Failed to retweet with thoughts using {account.username}. Error: {response.json()}")

        return redirect("retweet-thoughts")

    return render(request, "Sneat/actions.html")







def like_tweet(request):
    """Handles liking a tweet via Twitter API"""
    if request.method == "POST":
        tweet_id = request.POST.get("tweet_id")

        if not tweet_id:
            messages.error(request, "Please enter a Tweet ID.")
            return redirect("like")

        twitter_accounts = TwitterAccount.objects.all()

        for account in twitter_accounts:
            access_token = account.access_token
            like_url = f"https://api.twitter.com/2/users/{account.twitter_user_id}/likes"

            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            }
            payload = {
                "tweet_id": tweet_id
            }

            response = requests.post(like_url, json=payload, headers=headers)

            if response.status_code == 200:
                messages.success(request, f"Successfully liked tweet {tweet_id} using {account.username}")
            else:
                messages.error(request, f"Failed to like tweet {tweet_id} using {account.username}. Error: {response.json()}")

        return redirect("like")

    return render(request, "Sneat/actions.html")





def comment_on_tweet(request):
    """Handles commenting on a tweet via Twitter API"""
    if request.method == "POST":
        tweet_id = request.POST.get("tweet_id")
        comment = request.POST.get("comment")

        if not tweet_id or not comment:
            messages.error(request, "Please enter both Tweet ID and your comment.")
            return redirect("comment_on_tweet")

        twitter_accounts = TwitterAccount.objects.all()

        for account in twitter_accounts:
            access_token = account.access_token
            comment_url = "https://api.twitter.com/2/tweets"

            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            }
            payload = {
                "text": comment,
                "reply": {"in_reply_to_tweet_id": tweet_id}
            }

            response = requests.post(comment_url, json=payload, headers=headers)

            if response.status_code == 201:
                messages.success(request, f"Successfully commented on tweet using {account.username}")
            else:
                messages.error(request, f"Failed to comment using {account.username}. Error: {response.json()}")

        return redirect("comment_on_tweet")

    return render(request, "Sneat/actions.html")