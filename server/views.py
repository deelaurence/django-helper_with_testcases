from django.http import JsonResponse

def handle_404(request, exception):
    response_data = {'error': 'Not Found'}
    return JsonResponse(response_data, status=404)
