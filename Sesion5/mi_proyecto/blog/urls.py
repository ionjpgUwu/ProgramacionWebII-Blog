from django.urls import path
from . import views

urlpatterns = [
    path('lista_publicaciones/', views.lista_publicaciones, name='lista_publicaciones'),
    path('crear_publicacion/', views.crear_publicacion, name='crear_publicacion'),
    path('publicacion/<int:pk>', views.detalle_publicacion, name='detalle_publicacion'),
    path('publicacion/<int:pk>/comentar/', views.agregar_comentario, name='agregar_comentario'),
    path('usuarios/', views.lista_usuarios, name='lista_usuarios'),
    path('comentario/<int:pk>/editar', views.editar_comentario, name='editar_comentario'),
    path('publicacion/<int:pk>/editar/', views.editar_publicacion, name='editar_publicacion'),
    path('publicacion/<int:pk>/eliminar/', views.eliminar_publicacion, name='eliminar_publicacion'),
    path('logout/', views.logout_view, name='logout'),
    path('login/', views.login_view, name='login'),
    path('', views.pagina_principal, name='pagina_principal'),


]