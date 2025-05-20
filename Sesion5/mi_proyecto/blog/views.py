from django.shortcuts import render, redirect, get_object_or_404
from .models import Publicacion, Comentario
from django.contrib.auth.models import User
from .forms import PublicacionForm, ComentarioForm
from django.http import HttpResponseForbidden
from django.contrib.auth import logout
from django.contrib.auth import authenticate, login



def lista_publicaciones(request):
    publicaciones = Publicacion.objects.all()  # select * from publicacion
    return render(request,'blog/lista_publicaciones.html', {'publicaciones':publicaciones})

def crear_publicacion(request):
    if request.method == 'POST':
        form = PublicacionForm(request.POST)
        if form.is_valid():
            publicacion = form.save(commit=False)
            publicacion.usuario = request.user
            publicacion.save()
            return redirect('blog/home')
    else:
        form = PublicacionForm()
    return render(request,'blog/crear_publicacion.html',{'form':form})

def detalle_publicacion(request, pk):
    publicacion = get_object_or_404(Publicacion,pk=pk)
    comentarios = Comentario.objects.filter(publicacion = publicacion)
    form_comentario = ComentarioForm() if request.user.is_authenticated else None
    contexto ={
        'publicacion':publicacion,
        'comentarios':comentarios,
        'form_comentario':form_comentario,
    }
    return render(request, 'blog/detalle_publicacion.html',contexto)

def agregar_comentario(request, pk):
    publicacion = get_object_or_404(Publicacion, pk=pk)
    if request.method == 'POST':
        form = ComentarioForm(request.POST)
        if form.is_valid():
            comentario = form.save(commit=False)
            comentario.usuario = request.user
            comentario.publicacion = publicacion
            comentario.save()
            return redirect('detalle_publicacion', pk=pk)
def lista_usuarios(request):
    usuarios = User.objects.all()
    return render(request, 'blog/lista_usuarios.html', {'usuarios': usuarios})
from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect

def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        usuario = authenticate(request, username=username, password=password)
        if usuario is not None:
            login(request, usuario)
            return redirect('home')  # o a donde quieras redirigir
        else:
            return render(request, 'login.html', {'error': 'Credenciales incorrectas'})
    return render(request, 'login.html')
def editar_publicacion(request,pk):
    publicacion=get_object_or_404(Publicacion,pk=pk)
    if(publicacion.usuario !=request.user):
        return HttpResponseForbidden("no tiene permiso para editar la publicacion")
    if(request.method=="POST"):
        form=PublicacionForm(request.POST,instance=publicacion)
        if form.is_valid():
            form.save()
            return redirect('detalle_publicacion',pk=publicacion.pk)
    else:
        form = PublicacionForm(instance=publicacion)
    return render(request,'blog/editar_publicacion.html',{'form':form})       
def eliminar_publicacion(request,pk):
    publicacion=get_object_or_404(Publicacion,pk=pk)
    if(publicacion.usuario !=request.user):
        return HttpResponseForbidden("no tiene permiso para editar la publicacion")
    if(request.method=="POST"):
        publicacion.delete()
        return redirect('lista_publicaciones')
    return render(request,'blog/confirmar_eliminacion.html',{'publicacion':publicacion})       


def editar_comentario(request,pk):
    comentario=get_object_or_404(comentario,pk=pk)
    if request.user != comentario.usuario:
        return HttpResponseForbidden("no puedes editar este comentario")
    if request.method=='POST':
        form=ComentarioForm(request.POST, instance=comentario)
        if form.is_valid():
            form.save()
            return redirect('detalle_publicacion', pk=comentario.publicacion.pk)
    else:
        form=ComentarioForm(instance=comentario)
    return render(request,'blog/editar_comentario.html',{'form':form})

def logout_view(request):
    logout(request)
    return redirect('pagina_principal')  

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        usuario = authenticate(request, username=username, password=password)
        if usuario is not None:
            login(request, usuario)
            return redirect('pagina_principal') 
        else:
            return render(request, 'blog/login.html', {'error': 'Credenciales incorrectas'})
    return render(request, 'blog/login.html')

def pagina_principal(request):
    return render(request, 'blog/pagina_principal.html', {'usuario': request.user})

