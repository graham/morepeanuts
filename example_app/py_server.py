import datetime
import json
import base64

from flask import (
    Flask,
    request,
)

from googleapiclient.discovery import build
from oauth2client.client import AccessTokenCredentials

import httplib2

app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello, World!'

@app.route('/showme')
def showme():
    now = datetime.datetime.utcnow().isoformat() + 'Z' # 'Z' indicates UTC time

    token = json.loads(
        base64.urlsafe_b64decode(
            str(request.cookies.get('suez_authentication_key'))
        )
    )

    credentials = AccessTokenCredentials(
        token.get("access_token"),
        'my-user-agent/1.0')
    
    http = httplib2.Http()
    http = credentials.authorize(http)

    service = build('calendar', 'v3', http=http)

    response = []

    response.append('<html><body>')
    response.append('Getting the upcoming 10 events<br><br>')

    eventsResult = service.events().list(
        calendarId='primary', timeMin=now, maxResults=10, singleEvents=True,
        orderBy='startTime').execute()
    events = eventsResult.get('items', [])
        
    if not events:
        response.append('No upcoming events found.')
        return '<br>'.join(response)
        
    for event in events:
        start = event['start'].get('dateTime', event['start'].get('date'))
        response.append("<div>%s %s</div>" % (start, event['summary']))
        
    return ''.join(response)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=3000)

