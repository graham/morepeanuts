import datetime
import json
import base64

from flask import (
    Flask,
    request,
)

from oauth2client.client import AccessTokenCredentials

import httplib2
import dropbox

app = Flask(__name__)

@app.route('/')
def showme():
    token = json.loads(
        base64.urlsafe_b64decode(
            str(request.cookies.get('suez_authentication_key'))
        )
    )

    db = dropbox.Dropbox(token.get('access_token'))
    res = db.files_list_folder('')
    files = []

    for i in res.entries:
        files.append("<div>" + i.name + "</div>")
    return "hi" + '\n'.join(files)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=3001)

