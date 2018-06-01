---
title: "JWT-expiration-check-using-vue-and-django-rest-framework"
excerpt: "verify JWT expiration using middleware of django and vue intercept"
last_modified_at: 2018-06-01T19:05:01-05:00
tags: 
  - code
---

```javascript
// if once interceptor is set if works anywhere where axios is called
import axios from 'axios'
// js-cookie is awesome module which can handle cooki
import Cookies from 'js-cookie'
axios.interceptors.request.use(function (config) {
  let tokenCookie = Cookies.get('user-token')
  let token = null
  if (tokenCookie !== null && tokenCookie !== undefined) {
    try {
      token = JSON.parse(tokenCookie).data.token
    } catch (e) {
      token = tokenCookie
    }
  }
  if (config.method === 'get') {
    // axios using params when method is get
    config.params = (config.params !== undefined) ? config.params : {}
    if (token !== null) {
      config.params.token = token
    }
    console.log('ToKEN GET')
    console.log(config.params.token)
  } else {
    // axios using data when method is get
    config.data = (config.data !== undefined) ? config.data : {}
    if (token !== null) {
      config.data.token = token
    }
    console.log('ToKEN POST')
    console.log(config.data.token)
  }

  return config
}, function (error) {
  // Do something with request error
  return Promise.reject(error)
})
// Add a response interceptor
axios.interceptors.response.use(function (response) {
  let token = response.data.token

  if (token !== undefined) {
    let data = {token: token}
    console.log('ToKEN SAVE')
    console.dir(data)
    Cookies.set('user-token', {data: data})
  } else {
    console.log('ERRR')
  }
  return response
}, function (error) {
  // Do something with response error
  return Promise.reject(error)
})
```

set middleware in django setting.py

```python
MIDDLEWARE = [
  'django.middleware.security.SecurityMiddleware',
  'django.contrib.sessions.middleware.SessionMiddleware',
  'django.middleware.common.CommonMiddleware',
  'django.middleware.csrf.CsrfViewMiddleware',
  'django.contrib.auth.middleware.AuthenticationMiddleware',
  'django.contrib.messages.middleware.MessageMiddleware',
  'django.middleware.clickjacking.XFrameOptionsMiddleware',
  'corsheaders.middleware.CorsMiddleware',
  'middleware.authCheck.JwtExpiCheck'
]
```

and make middleware to verify jwt

```python
import re
from rest_framework.response import Response
from rest_framework import status,serializers
from rest_framework_jwt.serializers import VerifyJSONWebTokenSerializer,RefreshJSONWebTokenSerializer
from django.contrib.auth.models import User


class JwtExpiCheck():
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # jobs is done here
        # if get_response is called we go into view
        path = request.path
        is_passible = self.is_passible(path)
        response = None
        try:
            if is_passible:
                response = self.get_response(request)
            elif self.check_jwt(request):

                token = self.get_token(request)
                # refresh jwt token
                refreshed = RefreshJSONWebTokenSerializer().validate(attrs={'token': token})
                response = self.get_response(request)
                # set token to response
                # rest_framework.response.Response has data parameter
                response.data['token'] = refreshed['token']
                response.status = status.HTTP_200_OK
        except Exception as e:
            response = Response(status=status.HTTP_403_FORBIDDEN)
        finally:
            return response

    def is_passible(self, path):
        # check path is passible or need to be verified
        is_account = bool(re.match('^\/account\/.+', path))
        is_favicon = bool(re.match('^\/favicon.ico', path))
        is_home = bool(re.match('^\/home\/', path))
        if is_account or is_favicon or is_home:
            return True
        else:
            return False

    def check_jwt(self, request):

        token = self.get_token(request)
        data = {'token': token}
        try:
            # serializers.ValidationError occurs if token is expired
            valid_data = VerifyJSONWebTokenSerializer().validate(data)
        except serializers.ValidationError as e:
            raise serializers.ValidationError
        # model can be retrieved
        user = valid_data['user']
        return isinstance(user, User)

    def get_token(self, request):
        if request.method == 'GET':
            params = request.GET
        else:
            params = request.POST
        token = params['token']
        return token
```
