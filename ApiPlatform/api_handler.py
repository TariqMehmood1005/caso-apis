from rest_framework import status
from rest_framework.response import Response


class APIResponse:

    @staticmethod
    def HTTP_200_OK(data=None, message="Request successful"):
        return Response({
            'status': status.HTTP_200_OK,
            'code': "HTTP_200_OK",
            'message': message,
            'data': data
        }, status=status.HTTP_200_OK)

    @staticmethod
    def HTTP_201_CREATED(data=None, message="Resource created successfully"):
        return Response({
            'status': status.HTTP_201_CREATED,
            'code': "HTTP_201_CREATED",
            'message': message,
            'data': data
        }, status=status.HTTP_201_CREATED)

    @staticmethod
    def HTTP_400_BAD_REQUEST(message="Bad request", data=None):
        return Response({
            'status': status.HTTP_400_BAD_REQUEST,
            'code': "HTTP_400_BAD_REQUEST",
            'message': message,
            'data': data
        }, status=status.HTTP_400_BAD_REQUEST)

    @staticmethod
    def HTTP_401_UNAUTHORIZED(message="Unauthorized access", data=None):
        return Response({
            'status': status.HTTP_401_UNAUTHORIZED,
            'code': "HTTP_401_UNAUTHORIZED",
            'message': message,
            'data': data
        }, status=status.HTTP_401_UNAUTHORIZED)

    @staticmethod
    def HTTP_403_FORBIDDEN(message="Permission denied", data=None):
        return Response({
            'status': status.HTTP_403_FORBIDDEN,
            'code': "HTTP_403_FORBIDDEN",
            'message': message,
            'data': data
        }, status=status.HTTP_403_FORBIDDEN)

    @staticmethod
    def HTTP_404_NOT_FOUND(message="Resource not found", data=None):
        return Response({
            'status': status.HTTP_404_NOT_FOUND,
            'code': "HTTP_404_NOT_FOUND",
            'message': message,
            'data': data
        }, status=status.HTTP_404_NOT_FOUND)

    @staticmethod
    def HTTP_409_CONFLICT(message="Resource conflict", data=None):
        return Response({
            'status': status.HTTP_409_CONFLICT,
            'code': "HTTP_409_CONFLICT",
            'message': message,
            'data': data
        }, status=status.HTTP_409_CONFLICT)

    @staticmethod
    def HTTP_500_INTERNAL_SERVER_ERROR(message="Internal server error", data=None):
        return Response({
            'status': status.HTTP_500_INTERNAL_SERVER_ERROR,
            'code': "HTTP_500_INTERNAL_SERVER_ERROR",
            'message': message,
            'data': data
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @staticmethod
    def HTTP_503_SERVICE_UNAVAILABLE(message="Service unavailable", data=None):
        return Response({
            'status': status.HTTP_503_SERVICE_UNAVAILABLE,
            'code': "HTTP_503_SERVICE_UNAVAILABLE",
            'message': message,
            'data': data
        }, status=status.HTTP_503_SERVICE_UNAVAILABLE)

    @staticmethod
    def error(message="Internal server error", data=None):
        return Response({
            'status': status.HTTP_500_INTERNAL_SERVER_ERROR,
            'code': "HTTP_500_INTERNAL_SERVER_ERROR",
            'message': message,
            'data': data or None
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @staticmethod
    def HTTP_204_NO_CONTENT(message="No content", data=None):
        return Response({
            'status': status.HTTP_204_NO_CONTENT,
            'code': "HTTP_204_NO_CONTENT",
            'message': message,
            'data': data
        }, status=status.HTTP_204_NO_CONTENT)

    @staticmethod
    def HTTP_405_METHOD_NOT_ALLOWED(message="Method not allowed", data=None):
        return Response({
            'status': status.HTTP_405_METHOD_NOT_ALLOWED,
            'code': "HTTP_405_METHOD_NOT_ALLOWED",
            'message': message,
            'data': data
        }, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    @staticmethod
    def HTTP_406_NOT_ACCEPTABLE(message="Not acceptable", data=None):
        return Response({
            'status': status.HTTP_406_NOT_ACCEPTABLE,
            'code': "HTTP_406_NOT_ACCEPTABLE",
            'message': message,
            'data': data
        }, status=status.HTTP_406_NOT_ACCEPTABLE)

    @staticmethod
    def HTTP_415_UNSUPPORTED_MEDIA_TYPE(message="Unsupported media type", data=None):
        return Response({
            'status': status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            'code': "HTTP_415_UNSUPPORTED_MEDIA_TYPE",
            'message': message,
            'data': data
        }, status=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE)

    @staticmethod
    def HTTP_429_TOO_MANY_REQUESTS(message="Too many requests", data=None):
        return Response({
            'status': status.HTTP_429_TOO_MANY_REQUESTS,
            'code': "HTTP_429_TOO_MANY_REQUESTS",
            'message': message,
            'data': data
        }, status=status.HTTP_429_TOO_MANY_REQUESTS)

    @classmethod
    def HTTP_422_UNPROCESSABLE_ENTITY(cls, message, data):
        return Response({
            'status': status.HTTP_422_UNPROCESSABLE_ENTITY,
            'code': "HTTP_422_UNPROCESSABLE_ENTITY",
            'message': message,
            'data': data
        }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
