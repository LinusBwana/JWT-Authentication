from rest_framework.permissions import BasePermission
from rest_framework.exceptions import PermissionDenied

class IsActiveUser(BasePermission):
    """
    Allows access only to active, authenticated users.
    """
    def has_permission(self, request, view):
        user = request.user
        if user and user.is_authenticated and user.is_active:
            return True
        raise PermissionDenied(detail="You must be an active user to access this resource.")


class IsAdminUserOrReadOnly(BasePermission):
    """
    Allows full access to admin users, read-only for others.
    """
    def has_permission(self, request, view):
        if request.method in ('GET', 'HEAD', 'OPTIONS'):
            return True
        user = request.user
        return bool(user and user.is_authenticated and user.is_staff)


class IsAdminUser(BasePermission):
    """
    Allows full access only to admin users.
    """
    def has_permission(self, request, view):
        user = request.user
        if user and user.is_authenticated and user.is_staff:
            return True
        raise PermissionDenied(detail="You must be an admin to access this site.")