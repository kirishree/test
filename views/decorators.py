from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

default_auth_header = openapi.Parameter(
    'X-Auth-Token',
    in_=openapi.IN_HEADER,
    description="Keystone Auth Token",
    type=openapi.TYPE_STRING,
    required=True
)

def custom_schema(tags=None, responses=None):
    return swagger_auto_schema(
        
        tags=tags or ['Router Management'],
        manual_parameters=[default_auth_header],
        responses=responses or {200: "Json Response"}
    )
