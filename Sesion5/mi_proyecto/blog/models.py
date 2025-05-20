from django.db import models
from django.contrib.auth.models import User

# Create your models here.
class Publicacion(models.Model):
    titulo = models.CharField(max_length=50)
    contenido = models.TextField()
    fecha_creacion = models.DateTimeField(auto_now_add=True)
    usuario = models.ForeignKey(User, on_delete=models.CASCADE, related_name='publicaciones')         

    def __str__(self):
        return self.titulo

class Comentario(models.Model):
    contenido = models.TextField()
    fecha_creacion = models.DateTimeField(auto_now_add=True)
    publicacion = models.ForeignKey(Publicacion, on_delete=models.CASCADE, related_name='comentarios') 
    usuario = models.ForeignKey(User, on_delete=models.CASCADE, related_name='comentarios')            
    
    def __str__(self):
        return self.contenido

