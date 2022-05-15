#for rendering in json and helpful for the fronend
# customizing errors 
# responses are customized here
from rest_framework import renderers
import json

class UserRenderer(renderers.JSONRenderer):
    charset='utf-8'
    
    def render(self, data, accepted_media_type=None, renderer_context=None):
        response = ''

        if 'ErrorDetail' in str(data):
            response = json.dumps({'errors':data})
        
        else:
            response = json.dumps(data)

        return response