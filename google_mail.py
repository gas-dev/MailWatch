"""Google OAuth 2.0 outbound mail, Gmail API gmail.send only."""
import base64
import json
from urllib.parse import urlencode
import requests

AUTH_URL="https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL="https://oauth2.googleapis.com/token"
SEND_URL="https://gmail.googleapis.com/gmail/v1/users/me/messages/send"
SCOPE="https://www.googleapis.com/auth/gmail.send"

def authorization_url(client_id, redirect_uri, state):
    return AUTH_URL+"?"+urlencode({"client_id":client_id,"redirect_uri":redirect_uri,"response_type":"code","scope":SCOPE,"access_type":"offline","prompt":"consent","state":state})

def exchange_code(client_id, client_secret, redirect_uri, code):
    r=requests.post(TOKEN_URL,data={"client_id":client_id,"client_secret":client_secret,"redirect_uri":redirect_uri,"code":code,"grant_type":"authorization_code"},timeout=25)
    r.raise_for_status()
    data=r.json()
    if "refresh_token" not in data:raise RuntimeError("Google non ha fornito refresh_token. Revoca l'autorizzazione precedente e riprova.")
    return data["refresh_token"]

def send(client_id,client_secret,refresh_token,email_message):
    refresh=requests.post(TOKEN_URL,data={"client_id":client_id,"client_secret":client_secret,"refresh_token":refresh_token,"grant_type":"refresh_token"},timeout=25)
    refresh.raise_for_status()
    token=refresh.json()["access_token"]
    raw=base64.urlsafe_b64encode(email_message.as_bytes()).decode("ascii")
    response=requests.post(SEND_URL,headers={"Authorization":"Bearer "+token},json={"raw":raw},timeout=35)
    response.raise_for_status()
    result=response.json()
    if not result.get("id"):raise RuntimeError("Google Gmail API non ha restituito l'identificativo messaggio")
    return result["id"]
