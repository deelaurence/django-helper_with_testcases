import datetime
from django.contrib.auth import get_user_model
import json
from django.urls import reverse
from django.http import HttpResponseRedirect
from rest_framework.response import Response
from django.http import HttpResponseBadRequest
from django.http import JsonResponse
User = get_user_model()
class VerifyEmailMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Set request into another variable
        # to allow multiple reads from the request stream
        _request = request

        

        # Check if the request path is "/auth/api/token/"
        if _request.path == reverse('token_obtain_pair'):
            request_body = json.loads(_request.body.decode('utf-8'))
            user_email = request_body.get('email')
            
            # Check if the user with the given email exists
            if User.objects.filter(email=user_email).exists():
                user = User.objects.get(email=user_email)
                # If the user is not active, return a JsonResponse
                if user.is_active is False:
                    return JsonResponse({
                        "status": "error",
                        "code": 400,
                        "message": "Verify your email and proceed to login",
                    }, status=400)
                    
                elif user.is_google is True:
                    return JsonResponse({
                        "status": "error",
                        "code": 400,
                        "message": "You signed up with Google",
                    }, status=400)
                    
                else:
                    response = self.get_response(request)
                    return response
        response = self.get_response(request)
        return response

class UserActivityMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if request.user.is_anonymous:
            pass
        else:
            current_time = datetime.datetime.now()
            user = request.user
            user.last_seen = current_time
            user.save()
            print("Authorized user:", request.user)
        return response


class CustomErrorResponseMiddleware2:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if response.status_code >= 400:
            self.handle_error_response(response)
           
        else:
            self.handle_successful_response(response)

        return self.finalize_response(response)

    def handle_error_response(self, response):
        response_content = response.content.decode('utf8')

        if hasattr(response, 'data'):
            error_key, error_message = self.extract_error_details(response.data)

            response.data = {
                "status": "error",
                "code": response.status_code,
                "message": f"Invalid {error_key.replace('_', ' ')}, {error_message.replace('_', ' ')}",
            }
        else:
            response.data = {
                "status": "error",
                "code": response.status_code,
                "message": "An error occurred",
            }

    def handle_successful_response(self, response):
        
        if isinstance(response, HttpResponseRedirect):
            # Handle HttpResponseRedirect
            # For example, you might want to redirect the user to a specific URL
            redirect_url = response.url
            return HttpResponseRedirect(redirect_url)
        elif isinstance(response, Response) and response.data is not None:
            # Handle other successful responses with data
            response.data = {
                "status": "success",
                "code": response.status_code,
                "message": "Request was successful",
                "data": response.data,  # Include original data
            }
            

    def finalize_response(self, response):
        
        if hasattr(response, 'rendered_content'):
            response.content = response.rendered_content
            response['Content-Type'] = 'application/json'
            # return response
        else:
            if response.status_code == 404:
                return JsonResponse({
                    "status": "error",
                    "code": "Not found",
                    "message": "Requested resource not found",
                }, status=404)
        return response

    def extract_error_details(self, data):
        error_key = ""
        error_message = ""
        counter = 0
        for key, value in data.items():
            counter += 1
            error_detail = value

            if counter == 1:
                error_key = key
            if counter == 1:
                if isinstance(error_detail, str):
                    error_message += error_detail
                elif isinstance(error_detail, list):
                    error_message += error_detail[0]
                elif isinstance(error_detail, dict):
                    error_message += str(error_detail)
        print(f"Iteration {counter}: {key} - {value} with type of {type(value)} ")

        return error_key, error_message
    


#currently not used
class CustomErrorResponseMiddleware3:
    def __init__(self, get_response):
        self.get_response = get_response


    def __call__(self, request):
        response = self.get_response(request)
        # print(response.content.decode('utf8'))
        response_content=response.content.decode('utf8')
        # print(response.data)
        if response.status_code >= 400:
            if hasattr(response, 'data'):
                error_key = ""
                error_message = ""
                counter = 0  # Initialize counter variable

                for key, value in response.data.items():
                    counter += 1  # Increment the counter for each iteration
                    error_detail = value
                    if counter==1:
                        error_key = key

                    print(f"Iteration {counter}: {key} - {value} with type of {type(value)} ")

                    if counter == 1:
                        if isinstance(error_detail, str):
                            print("error_detail is a string")
                            error_message += error_detail
                        elif isinstance(error_detail, list):
                            print("error_detail is a list")
                            error_message += error_detail[0]
                        elif isinstance(error_detail, dict):
                            # Convert the dictionary to a string representation
                            print("error_detail is a dictionary")
                            error_message += str(error_detail)

                print(f"Custom error loop ran {counter} {'time' if counter==1 else 'times'}")


                response.data = {
                    "status": "error",
                    "code": response.status_code,
                    "message": f"Invalid {error_key}, {error_message}",
                }
            else:
                response.data = {
                    "status": "error",
                    "code": response.status_code,
                    "message": "An error occurred",
                }
        else:
            print("here")
            response.data = {
                "status": "success",
                "code": response.status_code,
                "message": "Request was successful",
                "data": response.data,  # Include original data
            }
        if hasattr(response, 'rendered_content'):
            response.content = response.rendered_content
            response['Content-Type'] = 'application/json'
        else:
            if response.status_code == 404:
                response = JsonResponse({
                            "status": "error",
                            "code": 404,
                            "message": "Requested resource not found",
                        }, status=404)
                return response
            else:
                return response
        
        return response
